; test-dns.zone.inc -- portable, domain-agnostic fixture for OpenDMARC's
; live test suite (--enable-live-tests)
; ===========================================================================
;
; This file has no hardcoded domain name anywhere in it.  Drop it into your
; own zone with $INCLUDE, having already set your own $ORIGIN beforehand --
; every name below either inherits that origin directly or builds on it
; with a relative, non-terminal $ORIGIN switch (see "$ORIGIN dmarcwalk"
; below).  Point whatever test domain you chose at it via the matching
; #define (see issue #432 in trusteddomainproject/OpenDMARC -- that wiring
; doesn't exist yet, this file is the template waiting for it).
;
; Every value here is a placeholder: fake hostnames (mailserver01,
; mailserver02, webhost), RFC 1918 (10.0.0.0/8) and RFC 3849 documentation
; (2001:db8::/32) addresses that nobody delivers mail to or otherwise
; depends on.  Nothing here needs to resolve to anything real; the tests
; only check the SPF/DMARC string-matching logic, not actual connectivity.
; This is deliberately the disaster-recovery copy: if whoever maintains
; the live fixture domain today is unavailable, anyone can stand this zone
; up fresh under a domain of their own and the test suite keeps working.
;
; No $ORIGIN directive is needed for the records immediately below --
; they inherit whatever origin was active in your zone file at the
; $INCLUDE point.
;
; This file is written as an $INCLUDE fragment, not a standalone zone --
; it has no SOA and no NS, so it's meant to be pulled into a zone you've
; already set up.  If you'd rather use it as a complete, self-sufficient
; zone on its own, uncomment the SOA below (the "@" sigils mean it needs
; no real hostname either, just whatever domain you deploy this under)
; and add your own NS records -- that part can't be templated, since DNS
; requires actually-working, populated nameservers for the zone to
; resolve at all (most registrars require at least two).
;
; @             IN SOA  @ hostmaster ( 1 3600 900 604800 3600 )
; @             IN NS   ns1.example.com.        ; <- replace with your real nameservers
; @             IN NS   ns2.example.com.
;
; --- apex DMARC record ---------------------------------------------------
; Mirrors what dmarc_dns_test_record()/dmarc_dns_test_query()/
; dmarc_dns_test_xdomain_query() in test_dns_lookup.c need at the bare
; domain: a "v=DMARC1" record that's present and parses.  No rua=/ruf=
; needed -- those addresses aren't part of what the tests check, and
; deliberately aren't included here for both portability and privacy
; reasons (don't put a real mailbox address in a public template).
_dmarc          IN TXT  "v=DMARC1; p=none;"

; --- cross-domain report-authorization wildcard --------------------------
; Authorizes ANY reporting domain to send this domain cross-domain DMARC
; reports, so dmarc_dns_test_xdomain_query()'s authorization-exists case
; doesn't need a second, independently controlled domain.
*._report._dmarc        IN TXT  "v=DMARC1"

; --- SPF record -----------------------------------------------------------
; Exercises the same mechanism types opendmarc_spf2_run_test() checks:
; own "a", explicit "ip6:", "mx" (-> mailserver01), "a:mailserver02", and a
; trailing "~all" softfail catch-all for the no-match cases.
@               IN TXT  "v=spf1 a mx ip6:2001:db8::1 a:mailserver01 a:mailserver02 ~all"

; --- hosts the SPF record references --------------------------------------
@               IN A    10.0.0.1
@               IN MX   10 mailserver01
mailserver01    IN A    10.0.0.2
mailserver02    IN A    10.0.0.3

; --- existing host with no DMARC record of its own ------------------------
; webhost must keep resolving (A record below) but must NOT gain a
; _dmarc.webhost TXT record -- that absence is the "existing domain, no
; DMARC" test case.
webhost         IN A    10.0.0.4

; --- structural requirement: no wildcard A/AAAA at this level -------------
; The "definitely no such name" test cases, and the PSL-divergence case,
; both depend on arbitrary, unregistered subdomains here returning
; NXDOMAIN.  A catch-all wildcard A/AAAA record would silently break both.

; =====================================================================
; dmarcwalk subtree -- DMARCbis walk-mode fixture
; =====================================================================
;
; Exercises opendmarc_policy_query_dmarc() under all four
; OPENDMARC_WALK_MODE_* strategies (auto, psl, rfc7489, rfc9989).  Each
; subtree below is a self-contained scenario; the apex carries an explicit
; psd=y record so that no query in this section ever needs to walk out
; above it -- every walk started anywhere under this subtree terminates
; inside it.
;
; $ORIGIN below is relative (no trailing dot), so it builds on whatever
; origin was already active above -- no domain name hardcoded here either.
;
; Test cases (paths below are relative to wherever "dmarcwalk" ends up
; resolving; substitute your own base domain when reading these):
;
;   direct.dmarcwalk...
;       Has its own _dmarc record.  No walk should occur in any mode;
;       org domain == the queried domain itself for auto/psl/rfc7489/rfc9989.
;
;   sub.nopsd.dmarcwalk...  (query this; it has no record itself)
;       nopsd.dmarcwalk... has a record with no psd= tag (implicit psd=u).
;       rfc7489: one-level label-strip walk lands here directly
;       (org=nopsd.dmarcwalk..., fallback=yes).  rfc9989: accumulates this
;       record (no psd=, so it doesn't stop), continues upward, and stops
;       at the apex's psd=y -- per S4.10.2 step 2 the org domain is "one
;       label below" the psd=y domain, which resolves back to
;       nopsd.dmarcwalk... -- same answer as rfc7489, reached by a
;       different mechanism.  psl: opendmarc_get_tld() has no notion of
;       this subtree at all and will identify the parent zone's apex as
;       the registrable domain, so psl (and auto, if a PSL is loaded)
;       diverges to whatever that apex's record says -- this is the
;       interesting case showing PSL-vs-walk divergence, not a bug in the
;       fixture.
;
;   sub.psdn.dmarcwalk...  (query this; it has no record itself)
;       psdn.dmarcwalk... has a record with psd=n.  rfc9989 stops on the
;       first query (S4.10 step 2: psd=n means this level IS the org
;       domain) -- org=psdn.dmarcwalk....  rfc7489 lands on the same name
;       via its own one-level walk, since it has no concept of psd= and
;       just takes the first record it finds -- same answer, different
;       reasoning, useful as a sanity check that the two mechanisms agree
;       when there's only one plausible stopping point.
;
;   leaf.mid.psdy.dmarcwalk...  (query this; no record on this name or on
;   mid.psdy.dmarcwalk...)
;       psdy.dmarcwalk... has a record with psd=y.  rfc9989: walk queries
;       mid.psdy.dmarcwalk... (no record, accumulate nothing, continue),
;       then psdy.dmarcwalk... (psd=y, stop) -- org domain is "one label
;       below", i.e. mid.psdy.dmarcwalk....  rfc7489: walks the same two
;       levels but, having no psd= concept, just returns the first record
;       it actually finds -- psdy.dmarcwalk... itself, NOT
;       mid.psdy.dmarcwalk....  This is a genuine, intentional divergence
;       between the two modes; it is exactly the kind of case John Levine's
;       RFC 9989 clarification (see DMARCBIS-EDITOR-EMAIL.txt) was about.
;
;   d6.d5.d4.d3.d2.d1.eightlabel.dmarcwalk...  (query this; 10 labels
;   total, no record on this name)
;       d3.d2.d1.eightlabel.dmarcwalk... has a record with psd=n, and is
;       deliberately placed exactly 7 labels from the root of this
;       10-label name.  Per RFC 9989 S4.10 step 4, a domain with more than
;       8 labels is shortened to 7 before the walk begins, so rfc9989's
;       FIRST query should be exactly this name -- org domain found in a
;       single query (nqueries==1 if you're instrumenting it), proving the
;       8-label skip starts where the spec says, not at the literal
;       immediate parent.  rfc7489 has no such optimization: it walks one
;       label at a time from the leaf (d5..., d4..., then
;       d3.d2.d1.eightlabel...) and reaches the same record after three
;       queries instead of one -- same final org domain, different query
;       cost.
;
;   multirecord.dmarcwalk...  (query this directly; it carries two
;   separate v=DMARC1 TXT records)
;       Exercises the multiple-DMARC-records-at-one-name discard rule (RFC
;       7489 S6.6.3 step 5 / RFC 9989 S4.10 steps 2 and 6, fixed in commit
;       a25754c).  The direct query at multirecord.dmarcwalk... must come
;       back as no-record (not pick either TXT record).  The walk then
;       continues from there: rfc9989 goes one level up to the apex, finds
;       psd=y, and resolves org=multirecord.dmarcwalk... (one label below
;       the apex -- the very name whose direct record was just discarded,
;       which is correct: the discard applies to that one query, not to
;       the name's eligibility as an org domain found via a different
;       path).  rfc7489's one-level walk also reaches the apex next and,
;       having no psd= concept, takes its record as-is -- org domain ends
;       up as dmarcwalk... itself, diverging from rfc9989's answer.
;
$ORIGIN dmarcwalk

; Apex: psd=y containment boundary.  Caps every walk in this section so
; none of them can ever escape upward past it.
_dmarc          IN      TXT     "v=DMARC1; p=reject; psd=y;"

; --- direct: own record, no walk should ever be needed ---
_dmarc.direct   IN      TXT     "v=DMARC1; p=reject;"

; --- nopsd: record with no psd= tag; sub.nopsd has no record of its own ---
_dmarc.nopsd    IN      TXT     "v=DMARC1; p=quarantine;"

; --- psdn: record with explicit psd=n; sub.psdn has no record of its own ---
_dmarc.psdn     IN      TXT     "v=DMARC1; p=reject; psd=n;"

; --- psdy: record with explicit psd=y; mid.psdy and leaf.mid.psdy have no
; records of their own ---
_dmarc.psdy     IN      TXT     "v=DMARC1; p=none; psd=y;"

; --- eightlabel: record placed exactly 7 labels deep, to land precisely on
; the RFC 9989 S4.10 step 4 shortened starting point for a 10-label query
; (d6.d5.d4.d3.d2.d1.eightlabel.dmarcwalk...) ---
_dmarc.d3.d2.d1.eightlabel      IN      TXT     "v=DMARC1; p=reject; psd=n;"

; --- multirecord: two valid v=DMARC1 records at the same name; the direct
; query at this name must be discarded per the multiple-records rule ---
_dmarc.multirecord      IN      TXT     "v=DMARC1; p=reject;"
_dmarc.multirecord      IN      TXT     "v=DMARC1; p=quarantine;"
