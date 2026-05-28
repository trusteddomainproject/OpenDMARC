#!/usr/bin/perl
use strict;
use warnings;
use Net::DNS;
use IO::Select;
use Getopt::Long;
use POSIX qw(strftime);

# Survey DMARC psd= tag adoption across Public Suffix List entries.
#
# Reads the Mozilla Public Suffix List (public_suffix_list.dat) and queries
# _dmarc.<entry> for each entry, reporting psd= tag presence.
#
# Output (STDOUT): TSV - section, domain, psd_value, full_record
#   section:   "icann" or "private"
#   psd_value: "y", "n", "-" (dmarc present but no psd=), or "none" (no dmarc record)
#
# Summary CSV (--csv FILE): appends one row per run with timestamp + aggregate
# counts, suitable for plotting adoption over time.
#
# Progress/stats (STDERR): running count + final summary

my $concurrency = 200;
my $timeout     = 10;
my $infile      = 'public_suffix_list.dat';
my $csvfile;
my $nameserver;

GetOptions(
    'concurrency=i' => \$concurrency,
    'timeout=i'     => \$timeout,
    'input=s'       => \$infile,
    'csv=s'         => \$csvfile,
    'nameserver=s'  => \$nameserver,
) or die "Usage: $0 [--input FILE] [--csv FILE] [--concurrency N] [--timeout N] [--nameserver IP]\n";

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => $timeout,
    tcp_timeout => $timeout,
    retrans     => 1,
    retry       => 2,
    ($nameserver ? (nameservers => [$nameserver]) : ()),
);

# Parse PSL - returns list of [section, domain] pairs.
# Wildcards (*.foo) -> query foo. Exceptions (!foo.bar) -> skip.
# Tracks current section (icann/private).
sub parse_psl {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";

    my @entries;
    my $section = 'icann';

    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+|\s+$//g;

        if ($line =~ /BEGIN ICANN DOMAINS/)   { $section = 'icann';   next }
        if ($line =~ /BEGIN PRIVATE DOMAINS/) { $section = 'private'; next }
        next if $line =~ /^\/\//;  # comment
        next unless $line =~ /\S/; # blank

        next if $line =~ /^!/;     # exception - skip

        # Wildcard *.foo -> query foo itself
        $line =~ s/^\*\.//;

        # Skip entries that still contain * (e.g. bare *)
        next if $line =~ /\*/;

        push @entries, [$section, $line];
    }
    close($fh);
    return @entries;
}

my @entries = parse_psl($infile);
printf STDERR "Parsed %d PSL entries (%d ICANN, %d private)\n",
    scalar(@entries),
    scalar(grep { $_->[0] eq 'icann'   } @entries),
    scalar(grep { $_->[0] eq 'private' } @entries);

# Stats - split by section
my %stats = (
    icann   => { queued => 0, done => 0, dmarc => 0, psd_y => 0, psd_n => 0, psd_none => 0, errors => 0 },
    private => { queued => 0, done => 0, dmarc => 0, psd_y => 0, psd_n => 0, psd_none => 0, errors => 0 },
);

# In-flight: socket => [section, domain]
my %inflight;
my $sel = IO::Select->new;

my $total_done = 0;
my $progress_interval = 500;
my $next_progress     = $progress_interval;

sub dispatch {
    my ($section, $domain) = @_;
    my $socket = $resolver->bgsend("_dmarc.$domain", 'TXT');
    unless ($socket) {
        $stats{$section}{errors}++;
        $stats{$section}{done}++;
        $total_done++;
        return;
    }
    $inflight{$socket} = [$section, $domain];
    $sel->add($socket);
    $stats{$section}{queued}++;
}

sub harvest {
    my ($block) = @_;
    my @ready = $block ? $sel->can_read($timeout) : $sel->can_read(0);
    for my $sock (@ready) {
        my ($section, $domain) = @{ delete $inflight{$sock} };
        $sel->remove($sock);
        $stats{$section}{done}++;
        $total_done++;

        my $pkt = eval { $resolver->bgread($sock) };
        unless ($pkt) {
            $stats{$section}{errors}++;
            print join("\t", $section, $domain, 'none', ''), "\n";
            next;
        }

        my $rcode = $pkt->header->rcode;
        if ($rcode eq 'NXDOMAIN' || ($rcode eq 'NOERROR' && !($pkt->answer))) {
            print join("\t", $section, $domain, 'none', ''), "\n";
            next;
        }

        my $found = 0;
        for my $rr ($pkt->answer) {
            next unless $rr->type eq 'TXT';
            my $txt = join('', $rr->txtdata);
            next unless $txt =~ /^v=DMARC1\b/i;

            $found = 1;
            $stats{$section}{dmarc}++;

            my $psd;
            if ($txt =~ /\bpsd=([yn])/i) {
                $psd = lc($1);
                $stats{$section}{"psd_$psd"}++;
            } else {
                $psd = '-';
                $stats{$section}{psd_none}++;
            }

            print join("\t", $section, $domain, $psd, $txt), "\n";
            last;
        }

        unless ($found) {
            print join("\t", $section, $domain, 'none', ''), "\n";
        }
    }
}

# Print TSV header
print join("\t", "section", "domain", "psd", "record"), "\n";

for my $entry (@entries) {
    my ($section, $domain) = @$entry;

    dispatch($section, $domain);

    while (scalar(keys %inflight) >= $concurrency) {
        harvest(1);
    }
    harvest(0);

    if ($total_done >= $next_progress) {
        my $total = $stats{icann}{done} + $stats{private}{done};
        printf STDERR "  %d done, %d in-flight\n", $total, scalar(keys %inflight);
        $next_progress += $progress_interval;
    }
}

# Drain
while (%inflight) {
    harvest(1);
    if ($total_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight\n", $total_done, scalar(keys %inflight);
        $next_progress += $progress_interval;
    }
}

# Summary to STDERR
printf STDERR "\nDone.\n\n";
for my $sec (qw(icann private)) {
    my $s = $stats{$sec};
    printf STDERR "  %s:\n", uc($sec);
    printf STDERR "    Queried       : %d\n", $s->{done};
    printf STDERR "    Errors        : %d\n", $s->{errors};
    printf STDERR "    Have DMARC    : %d (%.1f%%)\n", $s->{dmarc}, $s->{done} ? 100*$s->{dmarc}/$s->{done} : 0;
    printf STDERR "      psd=y       : %d\n", $s->{psd_y};
    printf STDERR "      psd=n       : %d\n", $s->{psd_n};
    printf STDERR "      no psd=     : %d\n", $s->{psd_none};
    printf STDERR "\n";
}

# Append summary row to CSV if requested
if ($csvfile) {
    my $is_new = !-f $csvfile;
    open(my $cfh, '>>', $csvfile) or die "Cannot open $csvfile: $!\n";
    if ($is_new) {
        print $cfh join(',',
            'date',
            'icann_queried', 'icann_dmarc', 'icann_psd_y', 'icann_psd_n', 'icann_dmarc_no_psd',
            'private_queried', 'private_dmarc', 'private_psd_y', 'private_psd_n', 'private_dmarc_no_psd',
        ), "\n";
    }
    print $cfh join(',',
        strftime('%Y-%m-%d', localtime),
        $stats{icann}{done},   $stats{icann}{dmarc},   $stats{icann}{psd_y},   $stats{icann}{psd_n},   $stats{icann}{psd_none},
        $stats{private}{done}, $stats{private}{dmarc}, $stats{private}{psd_y}, $stats{private}{psd_n}, $stats{private}{psd_none},
    ), "\n";
    close($cfh);
    printf STDERR "Summary appended to %s\n", $csvfile;
}
