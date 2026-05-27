# OpenDMARC develop branch - change summary (post-1.4.2)

This document summarizes the changes merged into the `develop` branch during the triage and stabilization effort beginning May 2026. The effort reviewed all open pull requests and issues, merged or closed the majority, and added significant new reporting functionality.

---

## Security / correctness

- **Quarantine not deferred through ARC override**: When DMARC policy was `p=quarantine`, `smfi_quarantine()` was called before the ARC override check, meaning a valid ARC chain could not rescue a quarantined message. The quarantine call is now deferred until after the ARC policy evaluation. ARC override now also applies to quarantine results, not only rejections. (#321, issue #24)
- **`arc=pass` never appearing in aggregate reports**: The arc result value in the history file was compared against the wrong constant, so `arc=pass` was never written to XML reports. (#313, issue #282)
- **Received-SPF parser mishandling VERP envelope-from addresses**: `=` characters in VERP-encoded envelope senders (e.g. `user+list=example.com@host`) caused the Received-SPF parser to misread the result field. The parser now handles `=` correctly. (#300, issues #206, #221)
- **SPF regression: `env_from` set after `helo_dom` for libspf2**: When libspf2 was in use, the envelope-from domain was stored after the HELO domain, causing the SPF check to evaluate against the wrong identity. Fixed initialization order. (#328, issue #262)
- **`policy_published.domain` using From domain instead of record location**: The `<policy_published><domain>` element in aggregate reports used the RFC5322 From domain rather than the domain where the DMARC record was actually found (which may be the organizational domain). (#270)
- **`Arrival-Date` and `Delivery-Result` missing from failure reports**: The failure report (`message/feedback-report` MIME part) omitted `Arrival-Date:` and `Delivery-Result:` fields required by RFC 6591. These could not be populated because policy was enacted after the report was generated; the fix reorders the two operations. (#332, issue #22)
- **RFC5322 error reason not included in SMTP rejection response**: When `RequiredHeaders` rejected a message, the specific reason (e.g. "not exactly one Date field") was logged but not sent in the SMTP `550` response. Now calls `smfi_setreply()` with the reason string. (#333, issue #202)
- **Four crash and memory-safety bugs**: Fixed NULL pointer dereference in `opendmarc_spf_ipv6_explode()`, a use-after-free in ARC seal parsing, and two additional memory-safety issues. (#298, issues #18, #140, #152, #256)
- **arcdomain memory leak in `mlfi_eom`**: ARC domain strings allocated during message processing were not freed on the cleanup path. (#310, issue #182)
- **`HoldQuarantinedMessages` blocked by `RejectFailures`**: The condition controlling `smfi_quarantine()` was gated on `conf_rejectfail`, so `HoldQuarantinedMessages yes` had no effect unless `RejectFailures yes` was also set. The two options are now independent. (#302, issue #237)

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
- **`--workdir`**: Specify the directory for temporary report XML files (default `.`). Previously hardcoded. (#324)
- **`opendmarc-run` wrapper script**: New `contrib/opendmarc-run` script wraps `opendmarc-reports` and `opendmarc-import` with environment-variable-based configuration and sane defaults, suitable for cron or systemd timer use. (#324)
- **`opendmarc-reports` config file support**: Supports a config file for persistent option storage, reducing cron command-line length. (#324)
- **DKIM `auth_results` missing when selector not in `selectors` table**: If a DKIM selector was not present in the selectors table, the `auth_results` row was silently dropped from the report. (#324, issue #230)
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

## Authentication-Results parsing

- **`Authentication-Results` header authserv-id quoting**: When `AuthservIDWithJobID` was enabled, the job ID was appended without quoting, producing an invalid header when the composite value contained characters requiring quoting. (#311, issue #17)
- **`AuthservIDWithJobID` not applied to SPF result header**: The job ID was appended to the DMARC authserv-id but not to the authserv-id in the SPF authentication result field. (#311, issue #17)
- **ADMD-less `Authentication-Results` headers**: Some MTAs (notably Office 365) generate AR headers that omit the authserv-id entirely. The parser now recovers gracefully rather than discarding the result. (#329, issue #73)

---

## Build system and portability

- **`opendmarc-spf-parse.c` missing from `Makefile.am`**: The Received-SPF parser source file added in the crash fixes was not listed in `opendmarc_SOURCES`, causing a link failure on clean builds. (#335, issue #334)
- **Perl path hardcoded in report scripts**: `#!/usr/bin/perl` was hardcoded in `opendmarc-reports`, `opendmarc-import`, and related scripts. The path is now detected by `configure` and substituted as `@PERL@`. (#318)
- **`OPENDMARC_LIB_VERSION` always `0x00000000`** in GitHub release tarballs: The version constant was read from a generated header not present in the tarball. (#301, issue #235)
- **Missing DEFAULT values for `messages` columns**: Several columns lacked `DEFAULT` clauses, causing `opendmarc-import` to fail under MySQL/MariaDB strict mode when processing history files from older opendmarc versions that omitted those fields. (#324, issues #217, #219)

---

## CI

- **GitHub Actions CI workflow added**: Linux build and test on Ubuntu, running on push and pull request to `develop`. (#330)
- **miltertest built from standalone repository**: The CI workflow now clones the standalone `thegushi/miltertest` repository rather than building miltertest from the OpenDKIM source tree. (#331)
- **Perl syntax check for report scripts**: `perl -c` is now run over all four generated report scripts (`opendmarc-{expire,import,params,reports}`) as a CI step, with all required Perl module dependencies installed. (#336)
