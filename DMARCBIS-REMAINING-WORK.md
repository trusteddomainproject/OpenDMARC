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
  history preserved below.
- **RFC 9991 `SPF-DNS` ARF field**: new opt-in `LogSPFDNS` option (only
  meaningful with `SPFSelfValidate`). Real new code, as anticipated below
  -- libspf2 has a pluggable "DNS layer" system built exactly for this
  kind of interception (`SPF_dns_server_t`, chainable via `layer_below`);
  a new logging layer (`libopendmarc/opendmarc_spf_dns_log.c`) is spliced
  in above libspf2's own caching layer so it sees every SPF-record lookup
  regardless of cache hits, including domains reached via
  `include:`/`redirect=`, without altering evaluation behavior. This
  closes RFC 9991's SPF-DNS gap entirely; both fields originally listed
  as blocked in this section are now done. See CHANGES-202605.md for the
  full writeup.

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

Both RFC 6591 fields originally tracked here (`DKIM-Canonicalized-Header`/
`-Body` and `SPF-DNS`) have shipped -- see "Done" above. Nothing remaining
in this section.

### Bugs found along the way

- **`t-verify-authservid-jobid` test-ordering bug, fixed**: found while
  live-testing the `LogSPFDNS` work (that's what prompted actually
  getting a real-libspf2 build going, via `--with-spf
  --with-spf2-include=... --with-spf2-lib=...` -- the environment used
  for most of this DMARCbis work had been silently building against the
  built-in fallback SPF evaluator instead, an easy mistake since
  `--with-spf2` is a *different*, unrecognized flag that `configure`
  silently ignores rather than erroring on). Root-caused with `ktrace`
  (confirmed byte-perfect wire delivery of the macro) and `lldb`
  (breakpoints in both OpenDMARC and, via its exported-but-internal
  symbols, real libmilter itself): the test sends the `i` (job ID) macro
  scoped to the MAIL stage, then calls `mt.mailfrom()` without ever
  having called `mt.helo()` -- so miltertest auto-inserts a filler HELO
  command at that point, per its documented "fill in skipped steps"
  behavior. Real libmilter's `st_helo()` handler unconditionally clears
  any macros already stored for *later* protocol stages
  (`mi_clr_macros(ctx, CI_HELO+1)`, a correct, by-design safeguard
  against stale macros surviving from a prior transaction on the same
  connection) -- which wipes the just-stored MAIL-stage macro before it's
  ever read back, since it arrived earlier than the (delayed) HELO it's
  nominally supposed to follow. Not a bug in miltertest, real libmilter,
  or OpenDMARC's C code -- purely a test-script ordering issue, present
  identically in every test in this suite that sends the `i` macro this
  way (all of them), just never noticed elsewhere since no other test
  asserts on the delivered value. Fixed by adding an explicit
  `mt.helo()` call before the macro send in every affected test file
  (all eleven `t-verify-*.lua` files that send the `i` macro), not just
  the one that was actually failing.
- **`--with-spf2` now a hard configure error**: the flag that caused the
  above (silently building against the built-in fallback SPF evaluator
  instead of real libspf2, since `--with-spf` is the real flag and
  `--with-spf2` doesn't exist) now fails `configure` immediately with a
  message pointing at the correct flags, instead of the default
  autoconf behavior of a warning + silent continue. Verified both that
  `--with-spf2` now errors and that the legitimate
  `--with-spf --with-spf2-include=... --with-spf2-lib=...` combination
  still configures `HAVE_SPF2_H`/`WITH_SPF` correctly.
- **Four config directives silently rejected at startup**: fixed in the
  same session (`opendmarc-config.h`'s `dmarcf_config[]` validation table
  was missing `DMARCbisIgnorePct`, `DMARCbisWalkModeFallback`,
  `ReadCanonicalizedData`, and `LogSPFDNS`) -- see CHANGES-202605.md. Worth
  a standing reminder: this table is hand-maintained and separate from
  every `config_get()` call site, so a new directive silently fails at
  startup instead of a compile error until someone actually parses a
  config file containing it, which apparently hadn't happened for three
  of these four since they were introduced.

### Open decision, not just missing code

- **`!NNNk` RUA size-suffix syntax**: RFC 9990 Appendix C says this syntax
  is obsolete and receivers (i.e. OpenDMARC, acting as report generator)
  MUST ignore it. The restored PR #392 code (`check_size_restriction`)
  actively parses and enforces it, faithfully reproducing pre-regression
  behavior rather than the RFC 9990 text. Same shape of question as the
  `pct=` POLA decision: keep honoring it for senders who rely on it, or
  drop it now that it's back in front of you. Needs an explicit call, not
  a default.
