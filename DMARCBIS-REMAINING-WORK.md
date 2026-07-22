# DMARCbis remaining work

Tracks what's left across RFC 9989 (DMARC core), RFC 9990 (aggregate
reporting), and RFC 9991 (failure reporting) — the documents that obsolete
RFC 7489. Source of truth for the overall gap analysis is GitHub issue
[#371](https://github.com/trusteddomainproject/OpenDMARC/issues/371)
(`trusteddomainproject/OpenDMARC`); this file exists because that issue
predates most of the work below and doesn't get rewritten as items close.
Copies of the RFCs themselves are in the repo root (`rfc7489.txt`,
`rfc9989.txt`, `rfc9990.txt`, `rfc9991.txt`). `DMARCBIS-WALK-NOTES.txt` and
`DMARCBIS-EDITOR-EMAIL.txt` cover the DNS Tree Walk design questions
specifically (all resolved) and are not duplicated here.

## Done

- **RFC 9989 DNS Tree Walk**: walk-mode selection (PSL/RFC7489/RFC9989/AUTO),
  configurable fallback, secondary alignment walk, `opendmarc-check`
  comparison tooling. All open questions in `DMARCBIS-WALK-NOTES.txt`
  resolved. (#430, #431, #433)
- **RFC 9989 `t=`/`pct=`**: `t=` parsing, fetch accessor, and enforcement
  step-down (reject->quarantine->none). `pct=` deliberately kept for POLA,
  with `DMARCbisIgnorePct` for operators who want strict compliance. (#434)
- **RFC 9990 aggregate reporting**: `np`/`testing`/`discovery_method` in
  `policy_published`, namespace bumped to `dmarc-2.0`, `<pct>` removed
  (branch `feat/rfc9990-aggregate-reporting`).
- **RFC 9991 failure reporting**: `Identity-Alignment` and
  `DKIM-Domain`/`-Identity`/`-Selector` ARF headers, `ruf=` external
  destination verification + rate-limiting in `opendmarc-reports
  --forensic`, `psd=y` excludes `ruf=` (branch
  `feat/rfc9991-forensic-reporting`). Also restored PR #392's `rua=`
  destination verification, which had been silently lost, and fixed a
  NOERROR-vs-NXDOMAIN bug in it found via live testing.
- **RFC 9991 `DKIM-Canonicalized-Header`/`-Body` ARF fields**: new
  `ReadCanonicalizedData` option reads `X-DKIM-Canonicalized-Header`/`-Body`
  staging headers from an upstream OpenDKIM running the new
  `AddCanonicalizedData` directive (`trusteddomainproject/OpenDKIM` PR
  #423), correlates them to whichever DKIM signature is blamed for a DMARC
  failure, and copies the base64 payload into the failure report,
  re-folded to this codebase's own ARF-body convention. Staging headers
  are always stripped before final delivery regardless of the setting.
  See CHANGES-202605.md for the full writeup; cross-project design
  history preserved below. SPF-DNS remains open.

## Remaining

### RFC 9990 aggregate reporting

- **`pass` disposition value** (S3.1.1.9): `ActionDispositionType` now
  includes `pass` (message passed DMARC under an *enforcing* policy)
  alongside `none`/`quarantine`/`reject`. Current code only ever emits the
  original three. Not touched by the `np`/`testing`/`discovery_method` work.
- **`policy_test_mode` reason type** (S3.1.6): a `<reason><type>` value a
  report record should carry when `t=y` caused a policy step-down. Directly
  adjacent to work already done — `t=` enforcement and `<testing>` in
  `policy_published` both shipped, but this per-record annotation didn't.
- **`generator` element** (S3.1.1.3): identifies the report-generating
  software. Not implemented in `opendmarc-reports`. (Unrelated: the
  separate `contrib/dmarc-report-totext.pl` *consumer* tool already parses
  this field from other senders' reports — that's reading, not writing.)
- **`error` element** (S3.1.1.3/S3.1.5): describes processing errors
  encountered while evaluating the DMARC Policy Record. Not implemented.
- **DKIM signature priority + 100-signature cap** (S3.1.3): defines which
  signatures to include when a message has several (strict-aligned pass
  first, then relaxed, then others) and caps the list. Not implemented as
  specified.
- **Extension mechanism** (S3.2, S5): `<extension>` at file level,
  namespaced elements at record level. Low priority — only matters if
  extensions are actually adopted by report consumers.
- **`rf=`/`ri=` cleanup**: both tags were removed from the DMARC record
  format by RFC 9989. OpenDMARC still parses them into unused
  `DMARC_POLICY_T` fields (`rf`, `ri`). Minor; safe to remove.

### RFC 9991 failure reporting

- **`SPF-DNS` ARF field** (RFC 6591, required per-record-consulted):
  needs the actual DNS record content (RRTYPE + domain + record text) for
  every record consulted during SPF evaluation, including `include:`/
  `redirect=` sub-queries. libspf2's public API (what's actually linked in
  production, confirmed via `spf_response.h` on quark) doesn't expose this
  chain — only a human-readable summary. OpenDMARC's own built-in fallback
  SPF evaluator (`opendmarc_spf.c`, used only when libspf2 isn't linked)
  already tracks it internally via `stack[s].spf`/`stack[s].domain`, but
  that's not the path in use. Real fix: a custom `SPF_dns_*`-compatible
  logging layer chained onto the real resolver, so queries can be captured
  without patching libspf2 itself. Self-contained but real new code.

`DKIM-Canonicalized-Header`/`-Body` (the other RFC 6591 field originally
listed here as blocked) shipped -- see "Done" above. Design history: it
turned out to need less new work than expected, because OpenDKIM already
built the underlying capture mechanism for its own unrelated `SendReports`
feature (`dkimf_sigreport()`, `opendkim/opendkim.c:10098`, using
`dkim_sig_getreportinfo()` and `dkimf_base64_encode_file()`) -- confirmed
by reading the OpenDKIM source directly rather than assuming a new
DKIM-verification subsystem was required. The OpenDKIM-side half was
handed off via `RFC9991-CANONICALIZED-DATA-HANDOFF.md` in that repo and
landed as `AddCanonicalizedData` (PR #423); this repo's half landed as
`ReadCanonicalizedData` on `feat/rfc9991-forensic-reporting`.

### Open decision, not just missing code

- **`!NNNk` RUA size-suffix syntax**: RFC 9990 Appendix C says this syntax
  is obsolete and receivers (i.e. OpenDMARC, acting as report generator)
  MUST ignore it. The restored PR #392 code (`check_size_restriction`)
  actively parses and enforces it, faithfully reproducing pre-regression
  behavior rather than the RFC 9990 text. Same shape of question as the
  `pct=` POLA decision: keep honoring it for senders who rely on it, or
  drop it now that it's back in front of you. Needs an explicit call, not
  a default.
