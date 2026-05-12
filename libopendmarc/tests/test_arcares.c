/*
**  Copyright (c) 2025, The Trusted Domain Project.
**    All rights reserved.
**
**  Unit tests for ARC-Authentication-Results and ARC-Seal header parsing.
**
**  Regression coverage:
**    #183/#236 - SIGSEGV: large RSA signatures (>512 bytes) crashed the parser
**    #222/#186 - SIGABRT: malformed tokens with no '=' hit assert() in
**                strip_whitespace
**    #241/#242 - memory leaks and NULL dereferences in ARC header parsing
**    #305      - AAR parser rewritten using shared authres_parse state machine
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

#include "opendmarc-ar.h"
#include "opendmarc-arcares.h"
#include "opendmarc-arcseal.h"

static int pass = 0, fail = 0;

#define CHECK(desc, expr) do { \
	if (expr) { \
		pass++; \
	} else { \
		fprintf(stderr, "FAIL: %s\n", (desc)); \
		fail++; \
	} \
} while (0)

static void
repeat_char(char *buf, char c, size_t n)
{
	memset(buf, c, n);
	buf[n] = '\0';
}

int
main(int argc, char **argv)
{
	struct arcares          aar;
	struct arcares_arc_field arc_field;
	struct arcseal          as;
	/* 520 'a's: exceeds the old 512-byte token limit */
	char                    longval[520 + 1];
	char                    hdr[4200];
	int                     ret;

	repeat_char(longval, 'a', 520);

	/* ------------------------------------------------------------------ */
	/* opendmarc_arcares_parse: valid header                               */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_parse(
	    (u_char *)"i=1; example.com; arc=pass smtp.remote-ip=1.2.3.4; "
	              "dkim=pass header.d=example.com; "
	              "spf=pass smtp.mailfrom=example.com",
	    &aar);
	CHECK("arcares_parse valid: returns 0",     ret == 0);
	CHECK("arcares_parse valid: instance == 1", aar.instance == 1);
	CHECK("arcares_parse valid: authserv_id",
	      strcmp((char *)aar.payload.ares_host, "example.com") == 0);
	CHECK("arcares_parse valid: method count",  aar.payload.ares_count == 3);
	CHECK("arcares_parse valid: first method is arc",
	      aar.payload.ares_result[0].result_method == ARES_METHOD_ARC);
	CHECK("arcares_parse valid: arc=pass",
	      aar.payload.ares_result[0].result_result == ARES_RESULT_PASS);

	/* ------------------------------------------------------------------ */
	/* arcares_parse: malformed (no i= prefix)                             */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_parse((u_char *)"example.com; arc=pass", &aar);
	CHECK("arcares_parse no i= prefix: returns -1", ret == -1);

	/* ------------------------------------------------------------------ */
	/* arcares_parse: overlong authserv_id                                 */
	/*                                                                     */
	/* With the new authres_parse-based implementation, values longer than */
	/* the field width are truncated by strlcat. The parse succeeds.       */
	/* ------------------------------------------------------------------ */

	snprintf(hdr, sizeof hdr, "i=1; %s; arc=pass smtp.remote-ip=1.2.3.4",
	         longval);
	ret = opendmarc_arcares_parse((u_char *)hdr, &aar);
	CHECK("arcares_parse overlong authserv_id: returns 0",    ret == 0);
	CHECK("arcares_parse overlong authserv_id: instance set", aar.instance == 1);
	CHECK("arcares_parse overlong authserv_id: host stored",
	      strlen((char *)aar.payload.ares_host) > 0);

	/* ------------------------------------------------------------------ */
	/* opendmarc_arcares_arc_parse: valid result                           */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_parse(
	    (u_char *)"i=1; example.com; arc=pass smtp.remote-ip=1.2.3.4",
	    &aar);
	CHECK("arcares_parse for arc_parse test: returns 0", ret == 0);

	ret = opendmarc_arcares_arc_parse(&aar, &arc_field);
	CHECK("arcares_arc_parse valid: returns 0",   ret == 0);
	CHECK("arcares_arc_parse valid: result is pass",
	      arc_field.arcresult.result_result == ARES_RESULT_PASS);
	CHECK("arcares_arc_parse valid: smtpclientip",
	      strcmp((char *)arc_field.smtpclientip, "1.2.3.4") == 0);

	/* ------------------------------------------------------------------ */
	/* arcares_arc_parse: old-style client-ip property name               */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_parse(
	    (u_char *)"i=1; example.com; arc=pass smtp.client-ip=5.6.7.8",
	    &aar);
	CHECK("arcares_parse client-ip: returns 0", ret == 0);
	ret = opendmarc_arcares_arc_parse(&aar, &arc_field);
	CHECK("arcares_arc_parse client-ip: returns 0", ret == 0);
	CHECK("arcares_arc_parse client-ip: smtpclientip",
	      strcmp((char *)arc_field.smtpclientip, "5.6.7.8") == 0);

	/* ------------------------------------------------------------------ */
	/* arcares_arc_parse: no ARC result in header                          */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_parse(
	    (u_char *)"i=1; example.com; spf=pass smtp.mailfrom=example.com",
	    &aar);
	CHECK("arcares_parse no arc method: returns 0", ret == 0);
	ret = opendmarc_arcares_arc_parse(&aar, &arc_field);
	CHECK("arcares_arc_parse no arc method: returns -1", ret == -1);

	/* ------------------------------------------------------------------ */
	/* arcares_arc_parse: overlong result value (issue #183/#236)         */
	/*                                                                     */
	/* Values longer than the field width are truncated. Parse succeeds.  */
	/* ------------------------------------------------------------------ */

	snprintf(hdr, sizeof hdr,
	         "i=1; example.com; arc=pass smtp.remote-ip=%s", longval);
	ret = opendmarc_arcares_parse((u_char *)hdr, &aar);
	CHECK("arcares_parse overlong value: returns 0", ret == 0);
	ret = opendmarc_arcares_arc_parse(&aar, &arc_field);
	CHECK("arcares_arc_parse overlong value: returns 0", ret == 0);
	CHECK("arcares_arc_parse overlong value: ip stored",
	      strlen((char *)arc_field.smtpclientip) > 0);

	/* ------------------------------------------------------------------ */
	/* opendmarc_arcseal_parse: valid header                               */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcseal_parse(
	    (u_char *)"i=1; a=rsa-sha256; cv=pass; d=example.com; "
	              "s=sel1; t=1234567890; b=abc123",
	    &as);
	CHECK("arcseal_parse valid: returns 0",     ret == 0);
	CHECK("arcseal_parse valid: instance == 1", as.instance == 1);
	CHECK("arcseal_parse valid: domain",
	      strcmp((char *)as.signature_domain, "example.com") == 0);
	CHECK("arcseal_parse valid: selector",
	      strcmp((char *)as.signature_selector, "sel1") == 0);
	CHECK("arcseal_parse valid: cv",
	      strcmp((char *)as.chain_validation, "pass") == 0);

	/* ------------------------------------------------------------------ */
	/* arcseal_parse: token with no '=' — SIGABRT regression (#222/#186)  */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcseal_parse((u_char *)"i=1; none", &as);
	CHECK("arcseal_parse token with no '=': returns -1", ret == -1);

	/* ------------------------------------------------------------------ */
	/* arcseal_parse: long b= value — SIGSEGV regression (#183/#236)      */
	/*                                                                     */
	/* RSA 3072-bit signatures produce ~512-byte base64 values. After the */
	/* fix the parse succeeds and the value is stored (truncated if needed)*/
	/* ------------------------------------------------------------------ */

	snprintf(hdr, sizeof hdr,
	         "i=1; a=rsa-sha256; cv=pass; d=example.com; s=sel1; "
	         "t=1234567890; b=%s",
	         longval);
	ret = opendmarc_arcseal_parse((u_char *)hdr, &as);
	CHECK("arcseal_parse long b= (RSA 3072+): returns 0",  ret == 0);
	CHECK("arcseal_parse long b=: instance set",           as.instance == 1);
	CHECK("arcseal_parse long b=: signature_value stored", as.signature_value[0] != '\0');
	CHECK("arcseal_parse long b=: other fields preserved",
	      strcmp((char *)as.signature_domain, "example.com") == 0);

	printf("ARC header parsing: pass=%d, fail=%d\n", pass, fail);
	return fail;
}
