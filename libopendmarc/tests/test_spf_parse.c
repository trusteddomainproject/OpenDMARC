/*
**  Copyright (c) 2025, The Trusted Domain Project.
**    All rights reserved.
**
**  Unit tests for dmarcf_parse_received_spf().
**
**  Regression coverage:
**    #206 - VERP address with single '=' in local part: the parser reset its
**           value buffer mid-parse, leaving leftover bytes that corrupted the
**           extracted domain, producing a false DMARC fail.
**    #221 - VERP address with triple '===' in local part: multiple resets
**           accidentally walked the parser to the correct domain fragment, so
**           it produced the right answer for the wrong reason. Confirmed still
**           correct after the fix.
**  Also covers variants that expose the corruption in cases where #221's
**  accidental correctness does not apply.
*/

#include "build-config.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif

#ifdef USE_BSD_H
# include <bsd/string.h>
#endif

#ifdef USE_DMARCSTRL_H
# include <opendmarc_strl.h>
#endif

#include "opendmarc-spf-parse.h"

static int pass = 0, fail = 0;

#define CHECK(desc, expr) do { \
	if (expr) { \
		pass++; \
	} else { \
		fprintf(stderr, "FAIL: %s\n", (desc)); \
		fail++; \
	} \
} while (0)

int
main(int argc, char **argv)
{
	int ret;

	/* ------------------------------------------------------------------ */
	/* Baseline: clean address, no special characters in local part        */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (example.com: authorized) receiver=mail.example.com;"
	    " identity=mailfrom;"
	    " envelope-from=user@example.com;"
	    " client-ip=1.2.3.4",
	    "example.com");
	CHECK("clean address: returns PASS", ret == ARES_RESULT_PASS);

	ret = dmarcf_parse_received_spf(
	    "fail (example.com: not authorized) receiver=mail.example.com;"
	    " identity=mailfrom;"
	    " envelope-from=user@example.com;"
	    " client-ip=1.2.3.4",
	    "example.com");
	CHECK("clean fail: returns FAIL", ret == ARES_RESULT_FAIL);

	/* ------------------------------------------------------------------ */
	/* Wrong identity: should return NEUTRAL regardless of SPF result      */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (example.com: authorized) receiver=mail.example.com;"
	    " identity=helo;"
	    " envelope-from=user@example.com;"
	    " client-ip=1.2.3.4",
	    "example.com");
	CHECK("identity=helo: returns NEUTRAL", ret == ARES_RESULT_NEUTRAL);

	/* ------------------------------------------------------------------ */
	/* Domain mismatch: should return NEUTRAL                              */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (example.com: authorized) receiver=mail.example.com;"
	    " identity=mailfrom;"
	    " envelope-from=user@other.com;"
	    " client-ip=1.2.3.4",
	    "example.com");
	CHECK("domain mismatch: returns NEUTRAL", ret == ARES_RESULT_NEUTRAL);

	/* ------------------------------------------------------------------ */
	/* #206 — quoted envelope-from with single '=' in local part           */
	/*                                                                     */
	/* Before the fix: '=' inside the quoted value reset the value buffer, */
	/* so post-'=' chars overwrote from the start. The original write was  */
	/* longer, leaving leftover bytes that corrupted the domain tail.      */
	/* "emails.livestorminvites.com" → "emails.livestorminvites.comnts"   */
	/* Result: NEUTRAL (domain mismatch). After fix: PASS.                 */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (emails.livestorminvites.com: authorized)"
	    " receiver=mail2.open.com;"
	    " identity=mailfrom;"
	    " envelope-from=\"bounces+2309175-1e1a-antonioxh.morgents=open.com"
	                     "@emails.livestorminvites.com\";"
	    " helo=o5.emails.livestorminvites.com;"
	    " client-ip=168.245.94.251",
	    "emails.livestorminvites.com");
	CHECK("#206 quoted VERP single '=': returns PASS", ret == ARES_RESULT_PASS);

	/* ------------------------------------------------------------------ */
	/* #206 variant — unquoted single '=' in local part                    */
	/*                                                                     */
	/* Same corruption path but without quoting. The pre-'=' string is    */
	/* longer than the post-'=', so leftover bytes corrupt the domain.    */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (sender.example.com: authorized)"
	    " receiver=mx.example.com;"
	    " identity=mailfrom;"
	    " envelope-from=bounces+longlocalpart=recipient@sender.example.com;"
	    " client-ip=1.2.3.4",
	    "sender.example.com");
	CHECK("#206 variant unquoted single '=': returns PASS",
	      ret == ARES_RESULT_PASS);

	/* ------------------------------------------------------------------ */
	/* #221 — unquoted triple '===' in local part (Twitter-style VERP)    */
	/*                                                                     */
	/* Before the fix, multiple resets "walked" the parser to the last    */
	/* fragment, which happened to be correct. Confirmed still correct    */
	/* after the fix.                                                      */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "Pass (sender SPF authorized)"
	    " identity=mailfrom;"
	    " client-ip=199.59.150.72;"
	    " helo=spruce-goose-ac.twitter.com;"
	    " envelope-from=123456789-abcdefghijklmnop-johndoe===example.com"
	                    "@bounce.twitter.com;"
	    " receiver=johndoe@example.com",
	    "bounce.twitter.com");
	CHECK("#221 unquoted triple '===': returns PASS", ret == ARES_RESULT_PASS);

	/* ------------------------------------------------------------------ */
	/* #221 variant — double '==' where post-last-'=' is shorter          */
	/*                                                                     */
	/* With the old parser: first '=' resets, collects "=short@sender.com"*/
	/* second '=' resets again, collects "short@sender.com" (shorter than */
	/* original) — leftover bytes from first write corrupt domain tail.   */
	/* After fix: full address parsed correctly, domain is "sender.com".  */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (sender.com: authorized)"
	    " identity=mailfrom;"
	    " envelope-from=verylonglocalpart==short@sender.com;"
	    " client-ip=1.2.3.4",
	    "sender.com");
	CHECK("#221 variant double '==' with short tail: returns PASS",
	      ret == ARES_RESULT_PASS);

	/* ------------------------------------------------------------------ */
	/* Comment block in header value (parenthetical) — should be skipped  */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (this is a comment with = signs and ; semicolons)"
	    " identity=mailfrom;"
	    " envelope-from=user@example.com;"
	    " client-ip=1.2.3.4",
	    "example.com");
	CHECK("comment with '=' and ';': returns PASS", ret == ARES_RESULT_PASS);

	/* ------------------------------------------------------------------ */
	/* No trailing ';' — last key=value pair handled at end of string      */
	/* ------------------------------------------------------------------ */

	ret = dmarcf_parse_received_spf(
	    "pass (example.com: authorized)"
	    " identity=mailfrom;"
	    " envelope-from=user@example.com",
	    "example.com");
	CHECK("no trailing semicolon: returns PASS", ret == ARES_RESULT_PASS);

	printf("Received-SPF parsing: pass=%d, fail=%d\n", pass, fail);
	return fail;
}
