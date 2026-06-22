; gushi.org.zone.inc -- what's actually live on gushi.org today
; ===========================================================================
;
; This documents gushi.org's REAL, operational records that
; libopendmarc/tests/test_spf.c and parts of test_dns_lookup.c currently
; test against, for as long as those tests are wired to gushi.org
; directly.  It is NOT the portable fixture -- see
; testfiles/test-dns.zone.inc for that (a domain-agnostic template with no
; real values, meant to be stood up under any domain once the live tests
; gain a configurable test-domain switch; see issue #432 in
; trusteddomainproject/OpenDMARC).
;
; gushi.org's dmarcwalk.gushi.org subtree (the DMARCbis walk-mode fixture)
; isn't repeated here either: it's purely synthetic data with no
; production meaning, so the live zone is simply
; testfiles/test-dns.zone.inc's "dmarcwalk" section, deployed under
; gushi.org instead of a placeholder domain.  Nothing gushi.org-specific
; to document there.
;
; rua=/ruf= reporting addresses are intentionally omitted below -- they
; aren't part of what the tests check, and a real mailbox address has no
; place in this file regardless.
;
; This is NOT a standalone zone -- gushi.org carries plenty of content
; unrelated to OpenDMARC (mail, web, etc.).  This is a paste-in/$INCLUDE
; fragment, not a full zone file: the subset of records --enable-live-tests
; actually depends on.  If gushi.org's zone is ever rebuilt from scratch
; (new registrar, new DNS provider, a fat-fingered zone transfer), this is
; the checklist of what needs to come back.
;
; Tested by:
;   libopendmarc/tests/test_spf.c          (opendmarc_spf2_run_test)
;   libopendmarc/tests/test_dns_lookup.c   (dmarc_dns_test_record,
;                                            dmarc_dns_test_query,
;                                            dmarc_dns_test_xdomain_query)
;
$ORIGIN gushi.org.

; --- apex DMARC record ---------------------------------------------------
; Required by: dmarc_dns_test_record() ["_dmarc.gushi.org" found],
;              dmarc_dns_test_query() ["gushi.org" own-record case, and
;              the PSL-loaded case, since opendmarc_get_tld() collapses
;              dmarcwalk.gushi.org down to gushi.org and re-queries here],
;              dmarc_dns_test_xdomain_query() [same-org shortcut, and as
;              the destination domain for the cross-domain case].
; Only "v=DMARC1" needs to be present and parse.  gushi.org's real record
; also carries rua=/ruf= reporting addresses not shown here; their exact
; content is not part of the test contract.
_dmarc          IN TXT  "v=DMARC1; p=none; adkim=r; aspf=r; rf=afrf; sp=reject;"

; --- cross-domain report-authorization wildcard --------------------------
; Required by: dmarc_dns_test_record() ["DMARC _report record found" via
;              "dmarcwalk.gushi.org._report._dmarc.gushi.org", and the
;              literal "*._report._dmarc.gushi.org" wildcard-name case],
;              dmarc_dns_test_xdomain_query() [authorizes the
;              dmarcwalk.gushi.org -> gushi.org cross-domain report case].
; A literal "*" wildcard so ANY reporting domain is authorized to send
; gushi.org cross-domain DMARC reports.
*._report._dmarc        IN TXT  "v=DMARC1"

; --- SPF record -----------------------------------------------------------
; Required by: opendmarc_spf2_run_test().  All five PASS/FAIL cases there
; depend on the exact mechanisms below: own "a", explicit "ip6:", "mx"
; (-> prime), "a:prime.gushi.org", and the trailing "~all" softfail
; catch-all that the no-match cases rely on (DMARC_POLICY_SPF_OUTCOME_FAIL,
; since the test calls opendmarc_spf2_test() with softfail_okay_flag=FALSE).
@               IN TXT  "v=spf1 a mx ip6:2620:137:6000:10::142 a:prime.gushi.org a:quark.gushi.org ~all"

; --- hosts the SPF record and tests reference -----------------------------
@               IN A    149.20.68.145
@               IN MX   10 prime
prime           IN A    149.20.68.142
quark           IN A    149.20.68.143

; --- existing host with no DMARC record of its own ------------------------
; Required by: dmarc_dns_test_record() ["Existing domain, no DMARC" case].
; defaultsite must keep resolving (A record below) but must NOT gain a
; _dmarc.defaultsite.gushi.org TXT record -- that absence is the point of
; the test case.  (Also referenced by test_spf.c's "ptr:defaultsite.gushi.org"
; case in the non-libspf2 build path.)
defaultsite     IN A    149.20.68.145

; --- structural requirement: no wildcard A/AAAA under gushi.org ----------
; dmarc_dns_test_record()'s "_dmarc.nosuchhost.gushi.org" case and the
; PSL-divergence case in dmarc_dns_test_query() both depend on arbitrary,
; unregistered subdomains of gushi.org returning NXDOMAIN.  A catch-all
; wildcard A/AAAA record at "*.gushi.org" would silently break both.
