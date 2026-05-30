#!/usr/local/bin/perl
use strict;
use warnings;
use Net::DNS;
use IO::Select;
use Getopt::Long;
use POSIX qw(strftime);

# Query Public Suffix List entries for DMARC records, reporting psd= adoption.
# Tracks which public suffixes have published DMARC records and whether they
# include psd=y, indicating readiness for DMARCbis PSD DMARC.
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
# Progress/stats (STDERR): running count + final summary

my $concurrency = 200;
my $timeout     = 5;
my $infile      = 'public_suffix_list.dat';
my $max_entries = 0;   # 0 = unlimited
my $nameserver;        # undef = system default
my $icann_only  = 0;   # if set, skip private domains section
my $outfile;           # undef = use dated default

GetOptions(
    'concurrency=i' => \$concurrency,
    'timeout=i'     => \$timeout,
    'input=s'       => \$infile,
    'output=s'      => \$outfile,
    'max=i'         => \$max_entries,
    'nameserver=s'  => \$nameserver,
    'icann-only!'   => \$icann_only,
) or die "Usage: $0 [--input FILE] [--output FILE] [--concurrency N] [--timeout N] [--max N] [--nameserver IP] [--icann-only]\n";

my $run_date = strftime('%Y-%m-%d', localtime);

if (!defined($outfile)) {
    $outfile = sprintf('dmarc-psd-survey-%s.tsv', $run_date);
}

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => $timeout,
    tcp_timeout => $timeout,
    retrans     => 1,
    retry       => 1,
    ($nameserver ? (nameservers => [$nameserver]) : ()),
);

open(my $fh,  '<', $infile)  or die "Cannot open $infile: $!\n";
open(my $out, '>', $outfile) or die "Cannot open $outfile: $!\n";

# Stats
my $n_queued    = 0;
my $n_done      = 0;
my $n_dmarc     = 0;  # has v=DMARC1 record
my $n_psd       = 0;  # has psd= in record
my $n_psd_y     = 0;  # has psd=y
my $n_psd_n     = 0;  # has psd=n
my $n_errors    = 0;

# In-flight: socket => [ suffix, section, wildcard, exception ]
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
    $inflight{$socket} = [ $suffix, $section, $wildcard, $exception ];
    $sel->add($socket);
    $n_queued++;
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
            next;
        }

        my $rcode = $pkt->header->rcode;
        next if $rcode eq 'NXDOMAIN';
        next if $rcode eq 'NOERROR' && !($pkt->answer);

        for my $rr ($pkt->answer) {
            next unless $rr->type eq 'TXT';
            my $txt = join('', $rr->txtdata);
            next unless $txt =~ /^v=DMARC1\b/i;

            $n_dmarc++;

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

    dispatch($entry, $section, $wildcard, $exception);

    while (scalar(keys %inflight) >= $concurrency) {
        harvest(1);
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
    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc, %d psd=\n",
            $n_done, scalar(keys %inflight), $n_dmarc, $n_psd;
        $next_progress += $progress_interval;
    }
}

close($out);

printf STDERR "\nDone. Output written to %s\n", $outfile;
printf STDERR "  Suffixes queried : %d\n",                                                $n_done;
printf STDERR "  Errors           : %d\n",                                                $n_errors;
printf STDERR "  Have DMARC       : %d (%.1f%%)\n",          $n_dmarc, $n_done   ? 100*$n_dmarc/$n_done   : 0;
printf STDERR "  Have psd=        : %d (%.1f%% of DMARC)\n", $n_psd,   $n_dmarc  ? 100*$n_psd/$n_dmarc    : 0;
printf STDERR "    psd=y          : %d\n",                                                $n_psd_y;
printf STDERR "    psd=n          : %d\n",                                                $n_psd_n;
