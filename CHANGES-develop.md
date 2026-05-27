# OpenDMARC develop branch - change summary (post-1.4.2)

This document summarizes the changes merged into the `develop` branch during the triage and stabilization effort beginning May 2026. The effort reviewed all open pull requests and issues, merged or closed the majority, and added significant new reporting functionality.

---

## Security / correctness

- **Strict DMARC alignment incorrectly passing with PSL configured**: `opendmarc_policy_check_alignment` fell through to organizational-domain (PSL) resolution after the initial exact-match check failed, even in strict mode (`adkim=s` or `aspf=s`). This could produce a false aligned result - e.g. `From: user@sub.example.com` with a signing domain of `example.com` would pass strict alignment because the PSL lookup collapsed the From domain to `example.com`. RFC 7489 §3.1.1/3.1.2 requires exact match only in strict mode. (#354, issue #268)
- **Quarantine not deferred through ARC override**: When DMARC policy was `p=quarantine`, `smfi_quarantine()` was called before the ARC override check, meaning a valid ARC chain could not rescue a quarantined message. The quarantine call is now deferred until after the ARC policy evaluation. ARC override now also applies to quarantine results, not only rejections. (#321, issue #24)
- **`arc=pass` never appearing in aggregate reports**: The arc result value in the history file was compared against the wrong constant, so `arc=pass` was never written to XML reports. (#313, issue #282)
- **Received-SPF parser mishandling VERP envelope-from addresses**: `=` characters in VERP-encoded envelope senders (e.g. `user+list=example.com@host`) caused the Received-SPF parser to misread the result field. The parser now handles `=` correctly. (#300, issues #206, #221)
- **SPF regression: `env_from` set after `helo_dom` for libspf2**: When libspf2 was in use, the envelope-from domain was stored after the HELO domain, causing the SPF check to evaluate against the wrong identity. Fixed initialization order. (#328, issue #262)
- **`policy_published.domain` using From domain instead of record location**: The `<policy_published><domain>` element in aggregate reports used the RFC5322 From domain rather than the domain where the DMARC record was actually found (which may be the organizational domain). (#270, issue #142)
- **`Arrival-Date` and `Delivery-Result` missing from failure reports**: The failure report (`message/feedback-report` MIME part) omitted `Arrival-Date:` and `Delivery-Result:` fields required by RFC 6591. These could not be populated because policy was enacted after the report was generated; the fix reorders the two operations. (#332, issue #22)
- **RFC5322 error reason not included in SMTP rejection response**: When `RequiredHeaders` rejected a message, the specific reason (e.g. "not exactly one Date field") was logged but not sent in the SMTP `550` response. Now calls `smfi_setreply()` with the reason string. (#333, issue #202)
- **Four crash and memory-safety bugs**: Fixed NULL pointer dereference in `opendmarc_spf_ipv6_explode()`, a use-after-free in ARC seal parsing, and two additional memory-safety issues. (#298, issues #18, #140, #152, #256)
- **arcdomain memory leak in `mlfi_eom`**: ARC domain strings allocated during message processing were not freed on the cleanup path. (#310, issue #182)
- **`HoldQuarantinedMessages` blocked by `RejectFailures`**: The condition controlling `smfi_quarantine()` was gated on `conf_rejectfail`, so `HoldQuarantinedMessages yes` had no effect unless `RejectFailures yes` was also set. The two options are now independent. (#302, issue #237)
- **`opendmarc_util_cleanup` buffer off-by-one**: The length guard used `> buflen` instead of `>= buflen`, allowing a string of exactly `buflen` characters through without room for a null terminator. (#344)
- **`opendmarc_util_finddomain` mishandling quoted-pair in display names**: RFC5322 section 3.2.4 allows backslash-escaped characters inside quoted strings. A From header like `"\"Medtronic, Inc.\"" <user@example.com>` caused the escaped inner quote to close the quote context early, leaving the comma unquoted and truncating the address at the comma. The domain was then parsed as `Medtronic` rather than `example.com`, causing DMARC to reject a legitimate message. (#345, issue #72)
- **`check_domain` accidentally exported from libopendmarc ABI**: The function is file-local, has no header declaration, and does not follow the `opendmarc_` naming convention. Making it `static` removes it from the public symbol table. (#346)
- **Memory leak in `opendmarc_tld_read_file`**: The hash context allocated before `fopen()` was leaked when `fopen()` failed. (#347)
- **`Authentication-Results` headers inserted at wrong position**: All `dmarcf_insheader()` calls used index `1`, placing headers after the first existing header rather than before it. RFC 8601 sections 4 and 7.1 require the A-R header to precede the MTA's `Received` header; SpamAssassin and other verifiers rely on this ordering. Changed to index `0`. (#349, issue #23)
- **Unbalanced `>` in mail address parse silently ignored**: A From address like `user@example.net>` (missing the opening `<`) caused the domain to be parsed as `example.net>`, for which no DMARC record exists. The filter then skipped DMARC evaluation entirely, allowing forged mail through. Now returns a parse error. (#342, issue #113, #174)

---

## Aggregate reports (RFC 7489 compliance)

Significant gaps between the generated aggregate report XML and RFC 7489 requirements have been closed. Changes require schema additions; see **Schema changes** below.

- **`<version>` element missing**: RFC 7489 §8.2 requires `<version>1</version>` as the first child of `<feedback>`. Was never emitted. (#317, issue #52)
- **`<envelope_from>` missing from `<identifiers>`**: The envelope-from domain was not included. Now populated from the `messages` table; omitted (rather than emitted empty) for null reverse-path messages. (#317, issue #52)
- **`<scope>` missing from SPF `<auth_results>`**: RFC 7489 §8.2 requires `<scope>mfrom</scope>` or `<scope>helo</scope>` depending on which identifier SPF evaluated. Captured through all three code paths (Authentication-Results header, Received-SPF header, internal libspf2) and stored as `spf_scope` in the `messages` table. (#317, issue #52)
- **`<fo>` missing from `<policy_published>`**: The failure reporting options bitmask was not included. Fetched via `opendmarc_policy_fetch_fo()` and stored as `fo` in the `requests` table. (#317, issue #52)

---

## Failure reporting enhancements

- **Forensic (per-message failure) reporting added to `opendmarc-reports`**: New `--forensic` mode generates individual per-message failure reports in addition to or instead of aggregate reports. (#324)
- **StaleMARC suppression**: New `--stale-days N` option skips domains whose DMARC record has disappeared from DNS, avoiding reports for abandoned domains. (#324)
- **VERP bounce tracking for report address suppression**: `opendmarc-reports` can send aggregate reports with VERP-encoded envelope senders (`--verp`). Bounce handlers can then `INSERT` the failing address into a `suppressions` table to stop future reports to that address. (#324)
- **Database-driven report address suppression**: A `suppressions` table (full addresses or bare domains) is checked before sending each report, allowing persistent local overrides beyond the DNS-level `ruf=` mechanism. (#324)
- **HTTPS/HTTP aggregate report submission**: `opendmarc-reports` now supports `https://` and `http://` URIs in `rua=` tags for report submission per RFC 7489 §7.1, in addition to `mailto:`. (#324, issue #25 partial)
- **SMTP authentication and SSL for report submission**: New options `--smtp-username`, `--smtp-password`, `--smtp-ssl`, `--smtp-ssl-ca-file` allow `opendmarc-reports` to authenticate to and use TLS with the outbound SMTP server. (#324, issues #269)
- **`--report-bcc`**: Send blind copies of all aggregate reports to a fixed address, useful for local archiving. (#324, issue #25)
- **`--report-contact`**: New option to set the `<email>` element in `<report_metadata>` independently of the SMTP envelope sender. RFC 9990 section 3.1.1.3 defines this field as the contact address for the reporting organization, with no requirement that it match the transport addresses. Falls back to `--report-email` if not specified. (#362, issue #285)
- **`--workdir`**: Specify the directory for temporary report XML files (default `.`). Previously hardcoded. (#324)
- **`opendmarc-run` wrapper script**: New `contrib/opendmarc-run` script wraps `opendmarc-reports` and `opendmarc-import` with environment-variable-based configuration and sane defaults, suitable for cron or systemd timer use. (#324)
- **`opendmarc-reports` config file support**: Supports a config file for persistent option storage, reducing cron command-line length. (#324)
- **DKIM `auth_results` missing when selector not in `selectors` table**: If a DKIM selector was not present in the selectors table, the `auth_results` row was silently dropped from the report. (#324, issue #230)
- **Domain names stored with inconsistent case**: `opendmarc-import` stored domain names with whatever case appeared in the first history file entry for that domain. If a spammer's message arrived first with `EXAMPLE.COM`, all aggregate reports for that domain were labelled with that casing. Domains are now lowercased on import. MySQL's default case-insensitive collation means existing mixed-case rows remain functional; operators who want to normalize existing data can run `UPDATE domains SET name = LOWER(name)`. (#351)
- **MariaDB hang on integer parameters**: Integer parameters in `opendmarc-reports` SQL queries were passed as strings, triggering a known MariaDB Connector/Perl hang on strict-type-checking servers. Parameters are now explicitly bound with `SQL_INTEGER`. (#324, issue #196)
- **Timezone off-by-one in `--day` mode**: In `--day` mode, the domain selection query compared timestamps without date truncation, causing domains to be selected or skipped based on wall-clock time within the day rather than calendar day boundaries. (#324, issue #210)

---

## Schema changes

The following `ALTER TABLE` statements are required for existing installations. `opendmarc-reports` and `opendmarc-import` print warnings at startup if the relevant columns are missing.

```sql
-- Fix MySQL strict mode incompatibility (issue #289)
ALTER TABLE requests MODIFY lastsent TIMESTAMP NULL DEFAULT NULL;

-- RFC 7489 SPF scope reporting (issue #52)
ALTER TABLE messages ADD COLUMN spf_scope TINYINT NOT NULL DEFAULT '-1' AFTER spf;

-- RFC 7489 fo= reporting (issue #52)
ALTER TABLE requests ADD COLUMN fo TINYINT NOT NULL DEFAULT '0' AFTER pct;

-- Fix strict mode import failures for messages from older opendmarc versions
ALTER TABLE messages MODIFY spf TINYINT NOT NULL DEFAULT '0';
ALTER TABLE messages MODIFY align_dkim TINYINT UNSIGNED NOT NULL DEFAULT '5';
ALTER TABLE messages MODIFY align_spf TINYINT UNSIGNED NOT NULL DEFAULT '5';
ALTER TABLE messages MODIFY sigcount TINYINT UNSIGNED NOT NULL DEFAULT '0';
ALTER TABLE messages MODIFY arc TINYINT UNSIGNED NOT NULL DEFAULT '0';
ALTER TABLE messages MODIFY arc_policy TINYINT UNSIGNED NOT NULL DEFAULT '1';

-- VERP/suppression support (PR #324)
CREATE TABLE IF NOT EXISTS suppressions (
    id INT NOT NULL AUTO_INCREMENT,
    address VARCHAR(255) NOT NULL,
    added TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(255),
    PRIMARY KEY(id),
    UNIQUE KEY(address)
);
```

---

## Signal handling

- **SIGHUP now triggers config reload instead of shutdown**: SIGHUP was handled identically to SIGTERM, causing the filter to exit. Unix convention is that SIGHUP triggers a configuration reload in long-running daemons. The reload path already existed (previously reachable via SIGUSR1 only); SIGHUP is now folded into it. SIGTERM and SIGINT remain the shutdown signals. (#323, issue #322)

---

## Configuration options

- **`RequiredFrom` option added**: New boolean option that rejects messages lacking a From: field from which a domain can be extracted. Unlike `RequiredHeaders` (which enforces all RFC5322 header count restrictions), `RequiredFrom` enforces only the From field check, making it suitable for deployments where full RFC5322 compliance would reject too many legitimate messages. Prevents attackers from omitting the From header to evade DMARC evaluation. (#343)

---

## Utilities and minor fixes

- **`HoldQuarantinedMessages` duplicated in `opendmarc.conf.sample`**: The option appeared twice in the sample configuration file. Duplicate removed. (issue #165)
- **`opendmarc-check` printed first domain for all arguments**: When multiple domains were passed on the command line, the output header always showed `argv[1]` instead of the current argument. (#350)
- **Startup log suppresses empty brackets**: When started with no relevant command-line options, the daemon logged `opendmarc vX.Y starting ()`. The parentheses are now omitted when there are no options to show. (#348)
- **History file `arc` field values corrected in documentation**: The opendmarc/README documented the `arc` field as `0=pass, 2=fail`; the code has always written `0` (`ARES_RESULT_PASS`) or `7` (`ARES_RESULT_FAIL`). Documentation corrected to match. (#352, issue #214)
- **Duplicate `AUTHRESHDRNAME` macro removed**: `opendmarc-ar.h` defined `AUTHRESHDRNAME` as `"Authentication-Results"`, duplicating the existing `AUTHRESULTSHDR` in `opendmarc.h`. The duplicate was removed and all uses updated to `AUTHRESULTSHDR`. (#357, issue #20)

---

## Authentication-Results parsing

- **AR header with no-result rejected as invalid**: RFC 8601 §2.2 permits `Authentication-Results: example.com; none` as a valid header indicating no methods were evaluated. The parser treated this as a syntax error. Added state handling for the `none` token before falling through to normal method processing. (#267)
- **`Authentication-Results` header authserv-id quoting**: When `AuthservIDWithJobID` was enabled, the job ID was appended without quoting, producing an invalid header when the composite value contained characters requiring quoting. (#311, issue #17)
- **`AuthservIDWithJobID` not applied to SPF result header**: The job ID was appended to the DMARC authserv-id but not to the authserv-id in the SPF authentication result field. (#311, issue #17)
- **ADMD-less `Authentication-Results` headers**: Some MTAs (notably Office 365) generate AR headers that omit the authserv-id entirely. The parser now recovers gracefully rather than discarding the result. (#329, issue #73)
- **AR header with no-result rejected as invalid**: RFC 8601 §2.2 permits `Authentication-Results: example.com; none` as a valid header indicating no methods were evaluated. The parser treated this as a syntax error. (#267)
- **ARC-Authentication-Results parser rewritten using shared state machine**: The bespoke `strsep`-based AAR parser was replaced with the unified `authres_parse()` function that handles both AR and AAR headers. The old parser was fragile against whitespace and quoting variations and could not correctly extract client-IP from `remote-ip` properties. `struct arcares` now carries a `struct authres payload` rather than individual string fields. `MAXARESULTS` doubled to 32. (#355, issue #305)
- **Multiple ARC/ARC-Seal parser crashes**: Fixed SIGSEGV (large RSA signatures exceeding the 512-byte token limit), SIGABRT (malformed tokens with no `=` sign hitting `assert()` in `strip_whitespace`), memory leaks, and NULL pointer dereferences in ARC header parsing. Also fixed a memory leak where `as_hdr_new` was allocated but not freed on the invalid-header path. Unknown auth methods in AAR headers (e.g. `dara=` from Gmail) are now skipped rather than rejecting the entire header. CRLF line folding in AAR headers is now handled correctly. Adds `test_arcares` unit tests covering all these cases. (#296, issues #183, #186, #222, #236, #238, #241, #242)

**Open question**: The `dmarc=` and `spf=` results are currently emitted as separate `Authentication-Results` headers, which is what most downstream consumers (Rspamd, SpamAssassin, etc.) expect. RFC 8601 permits combining them into a single header, and a future `CombinedAuthservHeader` option could allow operators to opt in once they have verified their downstream software handles it. Worth coordinating with those projects before implementing.

---

## Build system and portability

- **`opendmarc-spf-parse.c` missing from `Makefile.am`**: The Received-SPF parser source file added in the crash fixes was not listed in `opendmarc_SOURCES`, causing a link failure on clean builds. (#335, issue #334)
- **Perl path hardcoded in report scripts**: `#!/usr/bin/perl` was hardcoded in `opendmarc-reports`, `opendmarc-import`, and related scripts. The path is now detected by `configure` and substituted as `@PERL@`. (#318)
- **`Switch` module dependency removed**: The report scripts used `Switch`, which was removed from core Perl in 5.36 and requires a separate CPAN install on modern systems. All `switch`/`case` blocks have been converted to `if`/`elsif`/`else`. (#336)
- **`OPENDMARC_LIB_VERSION` always `0x00000000`** in GitHub release tarballs: The version constant was read from a generated header not present in the tarball. (#301, issue #235)
- **Missing DEFAULT values for `messages` columns**: Several columns lacked `DEFAULT` clauses, causing `opendmarc-import` to fail under MySQL/MariaDB strict mode when processing history files from older opendmarc versions that omitted those fields. (#324, issues #217, #219)
- **libspf2 include/library paths not propagated to Makefiles**: `configure.ac` modified `CFLAGS` to pass the SPF2 include path to `AC_SEARCH_LIBS`, but autoconf does not propagate `CFLAGS` changes into generated Makefiles. This caused build failures in rpmbuild environments (Fedora/EPEL) where `CFLAGS` is pre-set by distribution policy. Paths are now appended to `CPPFLAGS` and `LDFLAGS` instead. (#287)

---

## CI

- **GitHub Actions CI workflow added**: Linux build and test on Ubuntu, running on push and pull request to `develop`. (#330)
- **miltertest built from standalone repository**: The CI workflow now clones the standalone `thegushi/miltertest` repository rather than building miltertest from the OpenDKIM source tree. (#331)
- **Perl syntax check for report scripts**: `perl -c` is now run over all four generated report scripts (`opendmarc-{expire,import,params,reports}`) as a CI step, with all required Perl module dependencies installed. (#336)
