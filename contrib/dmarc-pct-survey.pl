#!/usr/local/bin/perl
use strict;
use warnings;
use Net::DNS;
use IO::Select;
use Getopt::Long;
use POSIX qw(strftime);
use LWP::Simple qw(getstore);
use IO::Uncompress::Unzip qw(unzip $UnzipError);

# Query Umbrella top-1M domains for DMARC records, reporting pct=, psd=, and t= usage.
# Also checks RFC 7489 S 7.1 external reporting consent for every rua= and ruf= URI.
#
# If --input file does not exist, downloads it automatically from Cisco Umbrella.
#
# Output (--output or dated file): TSV
#   run_date:    ISO 8601 date of this run (YYYY-MM-DD), for multi-run aggregation
#   domain:      queried domain
#   pct:         numeric value if present, "-" if absent
#   psd:         "y", "n", or "-" if absent
#   t:           "y", "n", or "-" if absent
#   rua_bad:     comma-separated external rua= URIs lacking {policy}._report._dmarc.{dest}
#                consent records per RFC 7489 S 7.1; "-" if none problematic
#   ruf_bad:     same for ruf=
#   record:      full DMARC TXT record
#
# Extra output (--extra-output or dated file): TSV of _dmarc records found at label
#   levels above the queried domains that are NOT themselves in the top-1M input.
#   Columns: run_date, domain, triggered_by, trigger_has_dmarc, pct, psd, t, record
#   trigger_has_dmarc: 1 if the triggering domain itself had a v=DMARC1 record, 0 if not
#   triggered_by: the top-1M domain whose label walk first enqueued this parent.
# Progress/stats (STDERR): running count + final summary

my $umbrella_url = 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip';

my $concurrency  = 500;
my $timeout      = 5;
my $infile       = 'top-1m.csv';
my $max_domains  = 0;     # 0 = unlimited
my $nameserver;           # undef = system default
my $outfile;              # undef = use dated default
my $extrafile;            # undef = use dated default
my $summarylog   = 'dmarc-pct-survey-summary.tsv';

GetOptions(
    'concurrency=i'  => \$concurrency,
    'timeout=i'      => \$timeout,
    'input=s'        => \$infile,
    'output=s'       => \$outfile,
    'extra-output=s' => \$extrafile,
    'max=i'          => \$max_domains,
    'nameserver=s'   => \$nameserver,
    'summary-log=s'  => \$summarylog,
) or die "Usage: $0 [--input FILE] [--output FILE] [--extra-output FILE] [--summary-log FILE] [--concurrency N] [--timeout N] [--max N] [--nameserver IP]\n";

unless (-f $infile) {
    my $zipfile = $infile . '.zip';
    print STDERR "Downloading Umbrella top-1M from $umbrella_url ...\n";
    my $rc = getstore($umbrella_url, $zipfile);
    die "Download failed (HTTP $rc)\n" unless $rc == 200;
    print STDERR "Extracting $zipfile ...\n";
    unzip($zipfile, $infile) or die "Unzip failed: $UnzipError\n";
    unlink($zipfile);
    print STDERR "Saved to $infile\n";
}

my $run_date = strftime('%Y-%m-%d', localtime);

if (!defined($outfile)) {
    $outfile = sprintf('dmarc-pct-survey-%s.tsv', $run_date);
}
if (!defined($extrafile)) {
    $extrafile = sprintf('dmarc-pct-survey-%s-extra.tsv', $run_date);
}

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => $timeout,
    tcp_timeout => $timeout,
    retrans     => 1,
    retry       => 1,
    ($nameserver ? (nameservers => [$nameserver]) : ()),
);

open(my $fh,  '<', $infile)  or die "Cannot open $infile: $!\n";

# Stats
my $n_queued   = 0;
my $n_done     = 0;
my $n_dmarc    = 0;  # has v=DMARC1 record
my $n_pct      = 0;  # has pct= in record
my $n_psd      = 0;  # has psd= in record
my $n_psd_y    = 0;  # has psd=y
my $n_psd_n    = 0;  # has psd=n
my $n_t        = 0;  # has t= in record
my $n_t_y      = 0;  # has t=y
my $n_t_n      = 0;  # has t=n
my $n_pct100_noop = 0;  # p=reject or p=quarantine with pct=100 (a no-op)
my $n_none_pct    = 0;  # p=none with any pct= value (has no effect)
my $n_errors   = 0;
my $n_rua_ext_bad = 0;  # domains with at least one unconsented external rua=
my $n_ruf_ext_bad = 0;  # domains with at least one unconsented external ruf=

my %has_dmarc;  # domains that returned a v=DMARC1 record in the main phase

# Buffered main-phase results: domain => hashref of parsed fields + URI lists.
# Written to output only after the consent-check phase completes.
my %dmarc_found;
my @dmarc_order;  # preserve completion order for output

# Parent-walk tracking: domains we directly queried, and unlisted parents to check.
my %known_domains;
my %extra_parents;  # parent_domain => first_triggering_child

# In-flight: socket => [ domain, dispatch_time ]
my %inflight;
my $sel = IO::Select->new;

my $progress_interval = 10_000;
my $next_progress     = $progress_interval;

# Extract the host (destination domain) from a rua=/ruf= URI.
# Returns undef for unrecognised schemes.
sub extract_uri_host {
    my ($uri) = @_;
    if ($uri =~ /^mailto:[^@]+\@([^!>\s]+)/i) {
        return lc($1);
    }
    if ($uri =~ m{^https?://([^/:?\#\s]+)}i) {
        return lc($1);
    }
    return undef;
}

# Parse a comma-separated tag value (rua= or ruf=) into a list of URI strings.
sub parse_uri_list {
    my ($val) = @_;
    return map { s/^\s+|\s+$//gr } split(/,/, $val);
}

sub dispatch {
    my ($domain) = @_;
    my $qname  = "_dmarc.$domain";
    my $socket = $resolver->bgsend($qname, 'TXT');
    unless ($socket) {
        $n_errors++;
        $n_done++;
        return;
    }
    $inflight{$socket} = [ $domain, time() ];
    $sel->add($socket);
    $n_queued++;
}

sub harvest {
    my ($block) = @_;
    my @ready = $block ? $sel->can_read($timeout) : $sel->can_read(0);
    for my $sock (@ready) {
        my $meta   = delete $inflight{$sock};
        my $domain = $meta->[0];
        $sel->remove($sock);
        $n_done++;

        my $pkt = eval { $resolver->bgread($sock) };
        unless ($pkt) {
            $n_errors++;
            # record error for output phase
            $dmarc_found{"#error:$domain"} = undef;
            push @dmarc_order, "#error:$domain";
            next;
        }

        my $rcode = $pkt->header->rcode;
        next if $rcode eq 'NXDOMAIN';
        next if $rcode eq 'NOERROR' && !($pkt->answer);
        if ($rcode ne 'NOERROR') {
            $n_errors++;
            $dmarc_found{"#$rcode:$domain"} = undef;
            push @dmarc_order, "#$rcode:$domain";
            next;
        }

        for my $rr ($pkt->answer) {
            next unless $rr->type eq 'TXT';
            my $txt = join('', $rr->txtdata);
            next unless $txt =~ /^v=DMARC1\b/i;

            $n_dmarc++;
            $has_dmarc{$domain} = 1;

            my $pct = ($txt =~ /\bpct=(\d+)/i)  ? $1      : '-';
            my $psd = ($txt =~ /\bpsd=([yn])/i)  ? lc($1) : '-';
            my $t   = ($txt =~ /\bt=([yn])/i)    ? lc($1) : '-';
            my $p   = ($txt =~ /\bp=(\w+)/i)     ? lc($1) : '-';

            $n_pct++ if $pct ne '-';
            if ($psd ne '-') {
                $n_psd++;
                $n_psd_y++ if $psd eq 'y';
                $n_psd_n++ if $psd eq 'n';
            }
            if ($t ne '-') {
                $n_t++;
                $n_t_y++ if $t eq 'y';
                $n_t_n++ if $t eq 'n';
            }
            if (($p eq 'reject' || $p eq 'quarantine') && $pct eq '100') {
                $n_pct100_noop++;
            }
            if ($p eq 'none' && $pct ne '-') {
                $n_none_pct++;
            }

            # Parse rua= and ruf= URI lists for consent checking.
            my @rua_uris = ($txt =~ /\brua=([^;]+)/i) ? parse_uri_list($1) : ();
            my @ruf_uris = ($txt =~ /\bruf=([^;]+)/i) ? parse_uri_list($1) : ();

            $dmarc_found{$domain} = {
                pct      => $pct,
                psd      => $psd,
                t        => $t,
                txt      => $txt,
                rua_uris => \@rua_uris,
                ruf_uris => \@ruf_uris,
            };
            push @dmarc_order, $domain;
            last;  # only evaluate first v=DMARC1 record
        }
    }
}

sub reap_stale {
    my $now = time();
    for my $sock (keys %inflight) {
        if ($now - $inflight{$sock}[1] > $timeout * 2) {
            my ($domain) = @{$inflight{$sock}};
            delete $inflight{$sock};
            $sel->remove($sock);
            $n_errors++;
            $n_done++;
            $dmarc_found{"#timeout:$domain"} = undef;
            push @dmarc_order, "#timeout:$domain";
        }
    }
}

sub reap_stale_extra {
    my ($fh) = @_;
    my $now = time();
    for my $sock (keys %inflight) {
        if ($now - $inflight{$sock}[1] > $timeout * 2) {
            my ($domain) = @{$inflight{$sock}};
            delete $inflight{$sock};
            $sel->remove($sock);
            $n_errors++;
            print $fh "# timeout: $domain\n";
        }
    }
}

sub parent_labels {
    my ($domain) = @_;
    my @labels = split(/\./, $domain);
    my @parents;
    shift @labels;
    while (@labels) {
        push @parents, join('.', @labels);
        shift @labels;
    }
    return @parents;
}

sub harvest_extra {
    my ($fh, $n_extra_dmarc_ref, $block) = @_;
    my @ready = $block ? $sel->can_read($timeout) : $sel->can_read(0);
    for my $sock (@ready) {
        my $meta = delete $inflight{$sock};
        $sel->remove($sock);
        my ($domain, undef, $triggered_by) = @$meta;

        my $pkt = eval { $resolver->bgread($sock) };
        unless ($pkt) { $n_errors++; print $fh "# error: $domain\n"; next; }

        my $rcode = $pkt->header->rcode;
        next if $rcode eq 'NXDOMAIN';
        next if $rcode eq 'NOERROR' && !($pkt->answer);
        if ($rcode ne 'NOERROR') {
            $n_errors++;
            print $fh "# $rcode: $domain\n";
            next;
        }

        for my $rr ($pkt->answer) {
            next unless $rr->type eq 'TXT';
            my $txt = join('', $rr->txtdata);
            next unless $txt =~ /^v=DMARC1\b/i;

            $$n_extra_dmarc_ref++;

            my $pct = ($txt =~ /\bpct=(\d+)/i)  ? $1      : '-';
            my $psd = ($txt =~ /\bpsd=([yn])/i)  ? lc($1) : '-';
            my $t   = ($txt =~ /\bt=([yn])/i)    ? lc($1) : '-';

            my $trigger_has_dmarc = $has_dmarc{$triggered_by} ? 1 : 0;
            print $fh join("\t", $run_date, $domain, $triggered_by, $trigger_has_dmarc, $pct, $psd, $t, $txt), "\n";
            last;
        }
    }
}

print STDERR "Reading $infile, writing $outfile (buffered until consent checks complete)\n";
print STDERR "Concurrency=$concurrency, timeout=${timeout}s\n";

while (my $line = <$fh>) {
    chomp $line;
    next unless $line =~ /\S/;

    # Handle both "rank,domain" and plain "domain"
    my $domain = ($line =~ /^\d+,(.+)$/) ? $1 : $line;
    $domain =~ s/^\s+|\s+$//g;
    next unless $domain =~ /\./;

    $known_domains{$domain} = 1;
    for my $parent (parent_labels($domain)) {
        $extra_parents{$parent} //= $domain;
    }

    dispatch($domain);

    # Drain when we've filled the concurrency window
    while (scalar(keys %inflight) >= $concurrency) {
        harvest(1);
        reap_stale();
    }

    # Opportunistic non-blocking harvest
    harvest(0);

    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc, %d pct=, %d psd=, %d t=\n",
            $n_done, scalar(keys %inflight), $n_dmarc, $n_pct, $n_psd, $n_t;
        $next_progress += $progress_interval;
    }

    last if $max_domains && $n_queued >= $max_domains;
}

close($fh);

# Drain remaining in-flight queries
while (%inflight) {
    harvest(1);
    reap_stale();
    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc, %d pct=, %d psd=, %d t=\n",
            $n_done, scalar(keys %inflight), $n_dmarc, $n_pct, $n_psd, $n_t;
        $next_progress += $progress_interval;
    }
}

# --- Extra phase: walk parent labels not directly queried ---
delete $extra_parents{$_} for keys %known_domains;

open(my $extra, '>:encoding(UTF-8)', $extrafile) or die "Cannot open $extrafile: $!\n";
print $extra join("\t", "run_date", "domain", "triggered_by", "trigger_has_dmarc", "pct", "psd", "t", "record"), "\n";

my $n_extra_queued = 0;
my $n_extra_dmarc  = 0;

print STDERR "\nRunning parent-label walk, writing $extrafile ...\n";

for my $parent (sort keys %extra_parents) {
    my $triggered_by = $extra_parents{$parent};
    my $socket = $resolver->bgsend("_dmarc.$parent", 'TXT');
    unless ($socket) { $n_errors++; next; }
    $inflight{$socket} = [ $parent, time(), $triggered_by ];
    $sel->add($socket);
    $n_extra_queued++;

    while (scalar(keys %inflight) >= $concurrency) {
        harvest_extra($extra, \$n_extra_dmarc, 1);
        reap_stale_extra($extra);
    }
    harvest_extra($extra, \$n_extra_dmarc, 0);
}

while (%inflight) {
    harvest_extra($extra, \$n_extra_dmarc, 1);
    reap_stale_extra($extra);
}

close($extra);

# --- Consent check phase (RFC 7489 S 7.1) ---
#
# For every external rua= and ruf= URI found in the main phase, query
# {policy-domain}._report._dmarc.{dest-domain}.  A v=DMARC1 record there
# authorises the destination to receive reports on behalf of the policy domain.
# Absence means the address is unconsented and must be ignored per the RFC.

print STDERR "\nRunning RFC 7489 S 7.1 consent checks ...\n";

# %consent_result: "$policy_domain|$dest_domain" => 1 (ok) or 0 (missing/error)
my %consent_result;

# Build the list of unique (policy, dest) pairs that need checking.
my @consent_queue;
for my $domain (keys %dmarc_found) {
    next unless defined $dmarc_found{$domain};  # skip error/timeout sentinels
    my $data = $dmarc_found{$domain};
    for my $tag ('rua', 'ruf') {
        for my $uri (@{$data->{"${tag}_uris"}}) {
            my $dest = extract_uri_host($uri);
            next unless defined $dest;
            # Same domain (or a subdomain of it): no consent check required.
            next if $dest eq $domain || $dest =~ /\.\Q$domain\E$/i;
            my $key = "$domain|$dest";
            next if exists $consent_result{$key};
            $consent_result{$key} = undef;  # mark pending
            push @consent_queue, [$domain, $dest];
        }
    }
}

my $n_consent_total = scalar @consent_queue;
my $n_consent_done  = 0;
printf STDERR "  %d unique (policy, destination) pairs to check\n", $n_consent_total;

# Async consent check loop, reusing the same resolver and IO::Select.
my %consent_inflight;  # socket => [policy_domain, dest_domain, dispatch_time]
my $csel = IO::Select->new;

while (@consent_queue || %consent_inflight) {
    # Fill up to concurrency
    while (@consent_queue && scalar(keys %consent_inflight) < $concurrency) {
        my ($pdomain, $dest) = @{shift @consent_queue};
        my $qname = "${pdomain}._report._dmarc.${dest}";
        my $sock  = $resolver->bgsend($qname, 'TXT');
        if ($sock) {
            $consent_inflight{$sock} = [$pdomain, $dest, time()];
            $csel->add($sock);
        } else {
            $consent_result{"$pdomain|$dest"} = 0;
            $n_consent_done++;
        }
    }

    my @ready = $csel->can_read(%consent_inflight ? $timeout : 0);
    for my $sock (@ready) {
        my ($pdomain, $dest) = @{delete $consent_inflight{$sock}};
        $csel->remove($sock);
        my $key = "$pdomain|$dest";
        $n_consent_done++;

        my $pkt = eval { $resolver->bgread($sock) };
        if (!$pkt) {
            $consent_result{$key} = 0;
            next;
        }

        my $rcode = $pkt->header->rcode;
        if ($rcode eq 'NOERROR') {
            my $found = 0;
            for my $rr ($pkt->answer) {
                next unless $rr->type eq 'TXT';
                if (join('', $rr->txtdata) =~ /^v=DMARC1\b/i) {
                    $found = 1;
                    last;
                }
            }
            $consent_result{$key} = $found;
        } else {
            $consent_result{$key} = 0;  # NXDOMAIN or error: not consented
        }
    }

    # Reap stale consent queries
    my $now = time();
    for my $sock (keys %consent_inflight) {
        if ($now - $consent_inflight{$sock}[2] > $timeout * 2) {
            my ($pdomain, $dest) = @{delete $consent_inflight{$sock}};
            $csel->remove($sock);
            $consent_result{"$pdomain|$dest"} = 0;
            $n_consent_done++;
        }
    }

    if ($n_consent_done > 0 && $n_consent_total > 0 &&
        $n_consent_done % 1000 == 0) {
        printf STDERR "  consent checks: %d/%d done\n",
            $n_consent_done, $n_consent_total;
    }
}

# --- Write main output ---

open(my $out, '>:encoding(UTF-8)', $outfile) or die "Cannot open $outfile: $!\n";
print $out join("\t", "run_date", "domain", "pct", "psd", "t", "rua_bad", "ruf_bad", "record"), "\n";

for my $key (@dmarc_order) {
    # Error/timeout sentinels stored as "#type:domain"
    if ($key =~ /^#(.+?):(.+)$/) {
        print $out "# $1: $2\n";
        next;
    }

    my $domain = $key;
    my $data   = $dmarc_found{$domain};
    next unless defined $data;

    # Determine unconsented external URIs for rua= and ruf=.
    my %bad;
    for my $tag ('rua', 'ruf') {
        my @bad_uris;
        for my $uri (@{$data->{"${tag}_uris"}}) {
            my $dest = extract_uri_host($uri);
            next unless defined $dest;
            next if $dest eq $domain || $dest =~ /\.\Q$domain\E$/i;
            my $key2 = "$domain|$dest";
            if (!$consent_result{$key2}) {
                push @bad_uris, $uri;
            }
        }
        $bad{$tag} = @bad_uris ? join(',', @bad_uris) : '-';
    }

    $n_rua_ext_bad++ if $bad{rua} ne '-';
    $n_ruf_ext_bad++ if $bad{ruf} ne '-';

    print $out join("\t",
        $run_date, $domain,
        $data->{pct}, $data->{psd}, $data->{t},
        $bad{rua}, $bad{ruf},
        $data->{txt},
    ), "\n";
}

close($out);

printf STDERR "\nDone. Output written to %s\n", $outfile;
printf STDERR "  Domains queried : %d\n", $n_done;
printf STDERR "  Errors          : %d\n", $n_errors;
printf STDERR "  Have DMARC      : %d (%.1f%%)\n", $n_dmarc, $n_done   ? 100*$n_dmarc/$n_done   : 0;
printf STDERR "  Have pct=       : %d (%.1f%% of DMARC)\n", $n_pct,   $n_dmarc ? 100*$n_pct/$n_dmarc   : 0;
printf STDERR "  Have psd=       : %d (%.1f%% of DMARC)\n", $n_psd,   $n_dmarc ? 100*$n_psd/$n_dmarc   : 0;
printf STDERR "    psd=y         : %d\n", $n_psd_y;
printf STDERR "    psd=n         : %d\n", $n_psd_n;
printf STDERR "  Have t=         : %d (%.1f%% of DMARC)\n", $n_t,     $n_dmarc ? 100*$n_t/$n_dmarc     : 0;
printf STDERR "    t=y           : %d\n", $n_t_y;
printf STDERR "    t=n           : %d\n", $n_t_n;
printf STDERR "  p=reject/quarantine with pct=100 (no-op) : %d\n", $n_pct100_noop;
printf STDERR "  p=none with pct= (no effect)             : %d\n", $n_none_pct;
printf STDERR "RFC 7489 S 7.1 external reporting consent (%s):\n", $outfile;
printf STDERR "  Pairs checked               : %d\n", $n_consent_total;
printf STDERR "  Domains w/ unconsented rua= : %d\n", $n_rua_ext_bad;
printf STDERR "  Domains w/ unconsented ruf= : %d\n", $n_ruf_ext_bad;
printf STDERR "Parent-label walk (%s):\n", $extrafile;
printf STDERR "  Unlisted parents checked : %d\n", $n_extra_queued;
printf STDERR "  Unlisted parents w/DMARC : %d\n", $n_extra_dmarc;

my $is_new = !-f $summarylog;
open(my $sum, '>>', $summarylog) or die "Cannot open $summarylog: $!\n";
print $sum join("\t", qw(run_date queried errors have_dmarc pct_total psd_total psd_y psd_n t_total t_y t_n pct100_noop none_pct rua_ext_bad ruf_ext_bad)), "\n" if $is_new;
print $sum join("\t", $run_date, $n_done, $n_errors, $n_dmarc, $n_pct, $n_psd, $n_psd_y, $n_psd_n, $n_t, $n_t_y, $n_t_n, $n_pct100_noop, $n_none_pct, $n_rua_ext_bad, $n_ruf_ext_bad), "\n";
close($sum);
