#!/usr/local/bin/perl
use strict;
use warnings;
use Net::DNS;
use IO::Select;
use Getopt::Long;
use POSIX qw(strftime);

# Query every delegated TLD in the DNS root zone for DMARC records.
# Obtains the TLD list via AXFR from a root zone transfer server rather
# than a static file, so it always reflects current delegations.
#
# Default transfer server: xfr.lax.dns.icann.org (IANA's public xfr service).
# F-root (f.root-servers.net / 192.5.5.241) also works.
#
# Output (--output or dated file): TSV - run_date, tld, psd, record
#   run_date: ISO 8601 date of this run (YYYY-MM-DD)
#   tld:      bare TLD label (e.g. "com", "co.uk" is not here -- only root delegations)
#   psd:      "y", "n", or "-" if absent
#   record:   full DMARC TXT record
# Progress/stats (STDERR): running count + final summary

my $xfr_server   = 'xfr.lax.dns.icann.org';
my $concurrency  = 100;
my $timeout      = 5;
my $nameserver;           # undef = system default for _dmarc queries
my $outfile;              # undef = use dated default
my $summarylog   = 'dmarc-root-survey-summary.tsv';

GetOptions(
    'xfr-server=s'  => \$xfr_server,
    'concurrency=i' => \$concurrency,
    'timeout=i'     => \$timeout,
    'output=s'      => \$outfile,
    'nameserver=s'  => \$nameserver,
    'summary-log=s' => \$summarylog,
) or die "Usage: $0 [--xfr-server HOST] [--output FILE] [--summary-log FILE] [--concurrency N] [--timeout N] [--nameserver IP]\n";

my $run_date = strftime('%Y-%m-%d', localtime);

if (!defined($outfile)) {
    $outfile = sprintf('dmarc-root-survey-%s.tsv', $run_date);
}

# AXFR the root zone to get delegated TLDs.
print STDERR "Fetching root zone via AXFR from $xfr_server ...\n";

my $xfr_resolver = Net::DNS::Resolver->new(
    nameservers => [$xfr_server],
    usevc       => 1,
    tcp_timeout => 60,
);

my %tlds;
my @xfr = $xfr_resolver->axfr('.');
die "AXFR failed: " . $xfr_resolver->errorstring . "\n" unless @xfr;

for my $rr (@xfr) {
    next unless $rr->type eq 'NS';
    my $owner = lc($rr->owner);
    $owner =~ s/\.$//;       # strip trailing dot
    next unless length($owner);   # skip root '.' itself
    next if $owner =~ /\./;       # skip anything below TLD level
    $tlds{$owner} = 1;
}

my @tlds = sort keys %tlds;
printf STDERR "  %d delegated TLDs found\n", scalar @tlds;

# Now query _dmarc for each TLD.
my $resolver = Net::DNS::Resolver->new(
    udp_timeout => $timeout,
    tcp_timeout => $timeout,
    retrans     => 1,
    retry       => 1,
    ($nameserver ? (nameservers => [$nameserver]) : ()),
);

open(my $out, '>:encoding(UTF-8)', $outfile) or die "Cannot open $outfile: $!\n";

# Stats
my $n_done   = 0;
my $n_dmarc  = 0;
my $n_psd    = 0;
my $n_psd_y  = 0;
my $n_psd_n  = 0;
my $n_errors = 0;

# In-flight: socket => [ tld, dispatch_time ]
my %inflight;
my $sel = IO::Select->new;

my $progress_interval = 100;
my $next_progress     = $progress_interval;

sub reap_stale {
    my $now = time();
    for my $sock (keys %inflight) {
        if ($now - $inflight{$sock}[1] > $timeout * 2) {
            my ($tld) = @{$inflight{$sock}};
            delete $inflight{$sock};
            $sel->remove($sock);
            $n_errors++;
            $n_done++;
            print $out "# timeout: $tld\n";
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
        my ($tld) = @$meta;

        my $pkt = eval { $resolver->bgread($sock) };
        unless ($pkt) { $n_errors++; print $out "# error: $tld\n"; next; }

        my $rcode = $pkt->header->rcode;
        next if $rcode eq 'NXDOMAIN';
        next if $rcode eq 'NOERROR' && !($pkt->answer);
        if ($rcode ne 'NOERROR') {
            $n_errors++;
            print $out "# $rcode: $tld\n";
            next;
        }

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

            print $out join("\t", $run_date, $tld, $psd, $txt), "\n";
            last;
        }
    }
}

print $out join("\t", "run_date", "tld", "psd", "record"), "\n";
print STDERR "Querying _dmarc for ${\scalar @tlds} TLDs, writing $outfile, concurrency=$concurrency, timeout=${timeout}s\n";

for my $tld (@tlds) {
    my $socket = $resolver->bgsend("_dmarc.$tld", 'TXT');
    unless ($socket) { $n_errors++; next; }
    $inflight{$socket} = [ $tld, time() ];
    $sel->add($socket);

    while (scalar(keys %inflight) >= $concurrency) {
        harvest(1);
        reap_stale();
    }
    harvest(0);

    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc\n",
            $n_done, scalar(keys %inflight), $n_dmarc;
        $next_progress += $progress_interval;
    }
}

while (%inflight) {
    harvest(1);
    reap_stale();
    if ($n_done >= $next_progress) {
        printf STDERR "  %d done, %d in-flight, %d dmarc\n",
            $n_done, scalar(keys %inflight), $n_dmarc;
        $next_progress += $progress_interval;
    }
}

close($out);

printf STDERR "\nDone. Output written to %s\n", $outfile;
printf STDERR "  TLDs queried  : %d\n", $n_done;
printf STDERR "  Errors        : %d\n", $n_errors;
printf STDERR "  Have DMARC    : %d (%.1f%%)\n", $n_dmarc, $n_done ? 100*$n_dmarc/$n_done : 0;
printf STDERR "  Have psd=     : %d (%.1f%% of DMARC)\n", $n_psd, $n_dmarc ? 100*$n_psd/$n_dmarc : 0;
printf STDERR "    psd=y       : %d\n", $n_psd_y;
printf STDERR "    psd=n       : %d\n", $n_psd_n;

my $is_new = !-f $summarylog;
open(my $sum, '>>', $summarylog) or die "Cannot open $summarylog: $!\n";
print $sum join("\t", qw(run_date queried errors have_dmarc psd_total psd_y psd_n)), "\n" if $is_new;
print $sum join("\t", $run_date, $n_done, $n_errors, $n_dmarc, $n_psd, $n_psd_y, $n_psd_n), "\n";
close($sum);
