#!/usr/bin/perl
use strict;
use warnings;
use Net::DNS;
use IO::Select;
use Getopt::Long;
use POSIX qw(strftime);

# Query Umbrella top-1M domains for DMARC records, reporting pct= and psd= usage.
#
# Output (--output or STDOUT): TSV - run_date, domain, pct_value, psd_value, full_record
#   run_date:  ISO 8601 date of this run (YYYY-MM-DD), for multi-run aggregation
#   pct_value: numeric value if present, "-" if absent
#   psd_value: "y", "n", or "-" if absent
# Progress/stats (STDERR): running count + final summary

my $concurrency  = 500;
my $timeout      = 5;
my $infile       = 'top-1m.csv';
my $max_domains  = 0;     # 0 = unlimited
my $nameserver;           # undef = system default
my $outfile;              # undef = STDOUT

GetOptions(
    'concurrency=i' => \$concurrency,
    'timeout=i'     => \$timeout,
    'input=s'       => \$infile,
    'output=s'      => \$outfile,
    'max=i'         => \$max_domains,
    'nameserver=s'  => \$nameserver,
) or die "Usage: $0 [--input FILE] [--output FILE] [--concurrency N] [--timeout N] [--max N] [--nameserver IP]\n";

my $run_date = strftime('%Y-%m-%d', localtime);

if (!defined($outfile)) {
    $outfile = sprintf('dmarc-pct-survey-%s.tsv', $run_date);
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
my $n_queued   = 0;
my $n_done     = 0;
my $n_dmarc    = 0;  # has v=DMARC1 record
my $n_pct      = 0;  # has pct= in record
my $n_psd      = 0;  # has psd= in record
my $n_psd_y    = 0;  # has psd=y
my $n_psd_n    = 0;  # has psd=n
my $n_errors   = 0;

# In-flight: socket => domain
my %inflight;
my $sel = IO::Select->new;

my $progress_interval = 10_000;
my $next_progress     = $progress_interval;

sub dispatch {
    my ($domain) = @_;
    my $qname  = "_dmarc.$domain";
    my $socket = $resolver->bgsend($qname, 'TXT');
    unless ($socket) {
        $n_errors++;
        $n_done++;
        return;
    }
    $inflight{$socket} = $domain;
    $sel->add($socket);
    $n_queued++;
}

sub harvest {
    my ($block) = @_;
    my @ready = $block ? $sel->can_read($timeout) : $sel->can_read(0);
    for my $sock (@ready) {
        my $domain = delete $inflight{$sock};
        $sel->remove($sock);
        $n_done++;

        my $pkt = eval { $resolver->bgread($sock) };
        unless ($pkt) {
            $n_errors++;
            next;
        }

        my $rcode = $pkt->header->rcode;
        # NXDOMAIN and NOERROR-with-no-answers are normal (domain has no record)
        next if $rcode eq 'NXDOMAIN';
        next if $rcode eq 'NOERROR' && !($pkt->answer);

        for my $rr ($pkt->answer) {
            next unless $rr->type eq 'TXT';
            my $txt = join('', $rr->txtdata);
            next unless $txt =~ /^v=DMARC1\b/i;

            $n_dmarc++;

            my $pct = ($txt =~ /\bpct=(\d+)/i)  ? $1      : '-';
            my $psd = ($txt =~ /\bpsd=([yn])/i)  ? lc($1) : '-';

            $n_pct++ if $pct ne '-';
            if ($psd ne '-') {
                $n_psd++;
                $n_psd_y++ if $psd eq 'y';
                $n_psd_n++ if $psd eq 'n';
            }

            print $out join("\t", $run_date, $domain, $pct, $psd, $txt), "\n";
            last;  # only evaluate first v=DMARC1 record
        }
    }
}

print $out join("\t", "run_date", "domain", "pct", "psd", "record"), "\n";

print STDERR "Reading $infile, writing $outfile, concurrency=$concurrency, timeout=${timeout}s\n";

while (my $line = <$fh>) {
    chomp $line;
    next unless $line =~ /\S/;

    # Handle both "rank,domain" and plain "domain"
    my $domain = ($line =~ /^\d+,(.+)$/) ? $1 : $line;
    $domain =~ s/^\s+|\s+$//g;
    next unless $domain =~ /\./;

    dispatch($domain);

    # Drain when we've filled the concurrency window
    while (scalar(keys %inflight) >= $concurrency) {
        harvest(1);
    }

    # Opportunistic non-blocking harvest
    harvest(0);

    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc, %d pct=, %d psd=\n",
            $n_done, scalar(keys %inflight), $n_dmarc, $n_pct, $n_psd;
        $next_progress += $progress_interval;
    }

    last if $max_domains && $n_queued >= $max_domains;
}

close($fh);

# Drain remaining in-flight queries
while (%inflight) {
    harvest(1);
    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc, %d pct=, %d psd=\n",
            $n_done, scalar(keys %inflight), $n_dmarc, $n_pct, $n_psd;
        $next_progress += $progress_interval;
    }
}

close($out);

printf STDERR "\nDone. Output written to %s\n", $outfile;
printf STDERR "  Domains queried : %d\n", $n_done;
printf STDERR "  Errors          : %d\n", $n_errors;
printf STDERR "  Have DMARC      : %d (%.1f%%)\n", $n_dmarc, $n_done ? 100*$n_dmarc/$n_done : 0;
printf STDERR "  Have pct=       : %d (%.1f%% of DMARC)\n", $n_pct,  $n_dmarc ? 100*$n_pct/$n_dmarc  : 0;
printf STDERR "  Have psd=       : %d (%.1f%% of DMARC)\n", $n_psd,  $n_dmarc ? 100*$n_psd/$n_dmarc  : 0;
printf STDERR "    psd=y         : %d\n", $n_psd_y;
printf STDERR "    psd=n         : %d\n", $n_psd_n;
