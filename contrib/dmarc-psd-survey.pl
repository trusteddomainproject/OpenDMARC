#!/usr/local/bin/perl
use strict;
use warnings;
use Net::DNS;
use IO::Select;
use Getopt::Long;
use POSIX qw(strftime);
use LWP::Simple qw(getstore);
use Net::LibIDN qw(idn_to_ascii);
binmode(STDERR, ':encoding(UTF-8)');

# Query Public Suffix List entries for DMARC records, reporting psd= adoption.
# Tracks which public suffixes have published DMARC records and whether they
# include psd=y, indicating readiness for DMARCbis PSD DMARC.
#
# If --input file does not exist, downloads it automatically from publicsuffix.org.
#
# Input: public_suffix_list.dat from https://publicsuffix.org/list/
#
# Output (--output or dated file): TSV - run_date, suffix, section, wildcard, exception, psd, record
#   run_date:  ISO 8601 date of this run (YYYY-MM-DD), for multi-run aggregation
#   section:   "icann" or "private"
#   wildcard:  1 if the PSL entry was a wildcard (*.foo); suffix is the parent queried
#   exception: 1 if the PSL entry was an exception (!foo.bar)
#   psd:       "y", "n", or "-" if absent
#   record:    full DMARC TXT record
#
# Extra output (--extra-output or dated file): TSV of _dmarc records found at label
#   levels above PSL entries that are NOT themselves in the PSL.
#   Columns: run_date, domain, triggered_by, trigger_has_dmarc, psd, record
#   trigger_has_dmarc: 1 if the triggering PSL entry itself had a v=DMARC1 record, 0 if not
#   triggered_by: the PSL entry whose label walk first enqueued this parent.
# Progress/stats (STDERR): running count + final summary

my $psl_url     = 'https://publicsuffix.org/list/public_suffix_list.dat';

my $concurrency  = 200;
my $timeout      = 5;
my $infile       = 'public_suffix_list.dat';
my $max_entries  = 0;   # 0 = unlimited
my $nameserver;         # undef = system default
my $icann_only   = 0;   # if set, skip private domains section
my $outfile;            # undef = use dated default
my $extrafile;          # undef = use dated default
my $summarylog   = 'dmarc-psd-survey-summary.tsv';

GetOptions(
    'concurrency=i'  => \$concurrency,
    'timeout=i'      => \$timeout,
    'input=s'        => \$infile,
    'output=s'       => \$outfile,
    'extra-output=s' => \$extrafile,
    'summary-log=s'  => \$summarylog,
    'max=i'         => \$max_entries,
    'nameserver=s'  => \$nameserver,
    'icann-only!'   => \$icann_only,
) or die "Usage: $0 [--input FILE] [--output FILE] [--extra-output FILE] [--concurrency N] [--timeout N] [--max N] [--nameserver IP] [--icann-only]\n";

my $run_date = strftime('%Y-%m-%d', localtime);

unless (-f $infile) {
    print STDERR "Downloading PSL from $psl_url ...\n";
    my $rc = getstore($psl_url, $infile);
    die "Download failed (HTTP $rc)\n" unless $rc == 200;
    print STDERR "Saved to $infile\n";
}

if (!defined($outfile)) {
    $outfile = sprintf('dmarc-psd-survey-%s.tsv', $run_date);
}
if (!defined($extrafile)) {
    $extrafile = sprintf('dmarc-psd-survey-%s-extra.tsv', $run_date);
}

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => $timeout,
    tcp_timeout => $timeout,
    retrans     => 1,
    retry       => 1,
    ($nameserver ? (nameservers => [$nameserver]) : ()),
);

open(my $fh,  '<:encoding(UTF-8)', $infile)  or die "Cannot open $infile: $!\n";
open(my $out, '>:encoding(UTF-8)', $outfile) or die "Cannot open $outfile: $!\n";

# Stats
my $n_queued    = 0;
my $n_done      = 0;
my $n_dmarc     = 0;  # has v=DMARC1 record
my $n_psd       = 0;  # has psd= in record
my $n_psd_y     = 0;  # has psd=y
my $n_psd_n     = 0;  # has psd=n
my $n_errors    = 0;

my %has_dmarc;  # PSL entries that returned a v=DMARC1 record in the main phase

# Parent-walk tracking: entries we directly queried, and unlisted parents to check.
my %known_entries;
my %extra_parents;  # parent_domain => first_triggering_entry

# In-flight: socket => [ suffix, section, wildcard, exception, dispatch_time ]
my %inflight;
my $sel = IO::Select->new;

my $progress_interval = 500;
my $next_progress     = $progress_interval;

sub dispatch {
    my ($suffix, $section, $wildcard, $exception) = @_;
    my $qname  = "_dmarc.$suffix";
    my $socket = $resolver->bgsend($qname, 'TXT');
    unless ($socket) {
        $n_errors++;
        $n_done++;
        return;
    }
    $inflight{$socket} = [ $suffix, $section, $wildcard, $exception, time() ];
    $sel->add($socket);
    $n_queued++;
}

sub reap_stale {
    my $now = time();
    for my $sock (keys %inflight) {
        if ($now - $inflight{$sock}[4] > $timeout * 2) {
            my ($suffix) = @{$inflight{$sock}};
            delete $inflight{$sock};
            $sel->remove($sock);
            $n_errors++;
            $n_done++;
            print $out "# timeout: $suffix\n";
        }
    }
}

sub harvest {
    my ($block) = @_;
    my @ready = $block ? $sel->can_read($timeout) : $sel->can_read(0);
    for my $sock (@ready) {
        my $meta = delete $inflight{$sock};
        $sel->remove($sock);
        $n_done++;

        my ($suffix, $section, $wildcard, $exception) = @$meta;

        my $pkt = eval { $resolver->bgread($sock) };
        unless ($pkt) {
            $n_errors++;
            print $out "# error: $suffix\n";
            next;
        }

        my $rcode = $pkt->header->rcode;
        next if $rcode eq 'NXDOMAIN';
        next if $rcode eq 'NOERROR' && !($pkt->answer);
        if ($rcode ne 'NOERROR') {
            $n_errors++;
            print $out "# $rcode: $suffix\n";
            next;
        }

        for my $rr ($pkt->answer) {
            next unless $rr->type eq 'TXT';
            my $txt = join('', $rr->txtdata);
            next unless $txt =~ /^v=DMARC1\b/i;

            $n_dmarc++;
            $has_dmarc{$suffix} = 1;

            my $psd = ($txt =~ /\bpsd=([yn])/i) ? lc($1) : '-';

            if ($psd ne '-') {
                $n_psd++;
                $n_psd_y++ if $psd eq 'y';
                $n_psd_n++ if $psd eq 'n';
            }

            print $out join("\t", $run_date, $suffix, $section, $wildcard, $exception, $psd, $txt), "\n";
            last;  # only evaluate first v=DMARC1 record
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

# Extra-phase reap: inflight metadata is [ domain, dispatch_time, triggered_by ]
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

            my $psd = ($txt =~ /\bpsd=([yn])/i) ? lc($1) : '-';

            my $trigger_has_dmarc = $has_dmarc{$triggered_by} ? 1 : 0;
            print $fh join("\t", $run_date, $domain, $triggered_by, $trigger_has_dmarc, $psd, $txt), "\n";
            last;
        }
    }
}

print $out join("\t", "run_date", "suffix", "section", "wildcard", "exception", "psd", "record"), "\n";

my $section    = "icann";
my $in_private = 0;

print STDERR "Reading $infile, writing $outfile, concurrency=$concurrency, timeout=${timeout}s\n";

while (my $line = <$fh>) {
    chomp $line;

    # Track section
    if ($line =~ /===BEGIN PRIVATE DOMAINS===/) {
        $in_private = 1;
        $section = "private";
        next;
    }
    if ($line =~ /===END PRIVATE DOMAINS===/) {
        $in_private = 0;
        next;
    }

    next if $icann_only && $in_private;

    # Skip comments and blank lines
    next if $line =~ /^\/\//;
    next unless $line =~ /\S/;

    my ($wildcard, $exception) = (0, 0);
    my $entry = $line;
    $entry =~ s/^\s+|\s+$//g;

    if ($entry =~ s/^\*\.//) {
        # Wildcard entry: *.foo.bar — query the parent (foo.bar)
        $wildcard = 1;
    } elsif ($entry =~ s/^!//) {
        # Exception entry: !foo.bar — foo.bar is itself a PSD
        $exception = 1;
    }

    next unless $entry =~ /\S/;

    # Convert IDN labels to punycode if needed
    if ($entry =~ /[^\x00-\x7F]/) {
        my $ace = idn_to_ascii($entry, 'UTF-8');
        if (!defined($ace)) {
            printf STDERR "  skipping non-convertible IDN entry: %s\n", $entry;
            next;
        }
        $entry = $ace;
    }

    $known_entries{$entry} = 1;
    for my $parent (parent_labels($entry)) {
        $extra_parents{$parent} //= $entry;
    }

    dispatch($entry, $section, $wildcard, $exception);

    while (scalar(keys %inflight) >= $concurrency) {
        harvest(1);
        reap_stale();
    }
    harvest(0);

    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc, %d psd=\n",
            $n_done, scalar(keys %inflight), $n_dmarc, $n_psd;
        $next_progress += $progress_interval;
    }

    last if $max_entries && $n_queued >= $max_entries;
}

close($fh);

while (%inflight) {
    harvest(1);
    reap_stale();
    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc, %d psd=\n",
            $n_done, scalar(keys %inflight), $n_dmarc, $n_psd;
        $next_progress += $progress_interval;
    }
}

close($out);

# --- Extra phase: walk parent labels not directly queried ---
delete $extra_parents{$_} for keys %known_entries;

open(my $extra, '>:encoding(UTF-8)', $extrafile) or die "Cannot open $extrafile: $!\n";
print $extra join("\t", "run_date", "domain", "triggered_by", "trigger_has_dmarc", "psd", "record"), "\n";

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

printf STDERR "\nDone. Output written to %s\n", $outfile;
printf STDERR "  Suffixes queried : %d\n",                                                $n_done;
printf STDERR "  Errors           : %d\n",                                                $n_errors;
printf STDERR "  Have DMARC       : %d (%.1f%%)\n",          $n_dmarc, $n_done   ? 100*$n_dmarc/$n_done   : 0;
printf STDERR "  Have psd=        : %d (%.1f%% of DMARC)\n", $n_psd,   $n_dmarc  ? 100*$n_psd/$n_dmarc    : 0;
printf STDERR "    psd=y          : %d\n",                                                $n_psd_y;
printf STDERR "    psd=n          : %d\n",                                                $n_psd_n;
printf STDERR "Parent-label walk (%s):\n", $extrafile;
printf STDERR "  Unlisted parents checked : %d\n", $n_extra_queued;
printf STDERR "  Unlisted parents w/DMARC : %d\n", $n_extra_dmarc;

my $is_new = !-f $summarylog;
open(my $sum, '>>', $summarylog) or die "Cannot open $summarylog: $!\n";
print $sum join("\t", qw(run_date queried errors have_dmarc psd_total psd_y psd_n)), "\n" if $is_new;
print $sum join("\t", $run_date, $n_done, $n_errors, $n_dmarc, $n_psd, $n_psd_y, $n_psd_n), "\n";
close($sum);
