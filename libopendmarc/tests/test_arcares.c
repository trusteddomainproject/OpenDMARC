/*
**  Copyright (c) 2025, The Trusted Domain Project.
**    All rights reserved.
**
**  Unit tests for ARC-Authentication-Results and ARC-Seal header parsing.
**
**  Regression coverage:
**    #183/#236 - SIGSEGV: strip_whitespace returned NULL for tokens >= 512
**                bytes (e.g. 3072-bit RSA signatures), passed to strlcpy()
**    #222/#186 - SIGABRT: malformed tokens with no '=' caused strip_whitespace
**                to be called with NULL, hitting assert(string != NULL)
**    #241/#242 - memory leaks and NULL dereferences in ARC header parsing
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
	    (u_char *)"i=1; example.com; arc=pass; "
	              "dmarc=pass header.from=example.com; "
	              "dkim=pass header.d=example.com; "
	              "spf=pass smtp.mailfrom=example.com",
	    &aar);
	CHECK("arcares_parse valid: returns 0",     ret == 0);
	CHECK("arcares_parse valid: instance == 1", aar.instance == 1);
	CHECK("arcares_parse valid: authserv_id",
	      strcmp((char *)aar.authserv_id, "example.com") == 0);

	/* ------------------------------------------------------------------ */
	/* arcares_parse: token with no '=' — SIGABRT regression (#222/#186)  */
	/*                                                                     */
	/* tag_value = token_ptr where token_ptr is NULL after strsep finds   */
	/* no '='. atoi(NULL)/snprintf with NULL → crash before the fix.      */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_parse((u_char *)"noequals", &aar);
	CHECK("arcares_parse missing '=': returns -1", ret == -1);

	/* ------------------------------------------------------------------ */
	/* arcares_parse: overlong authserv_id — SIGSEGV regression (#242)    */
	/*                                                                     */
	/* strip_whitespace returned NULL for tokens >= 512 bytes; before the */
	/* fix strlcpy(authserv_id, NULL, ...) crashed. After the fix the     */
	/* parse succeeds and the value is truncated to fit the struct field.  */
	/* ------------------------------------------------------------------ */

	snprintf(hdr, sizeof hdr, "i=1; %s; arc=pass", longval);
	ret = opendmarc_arcares_parse((u_char *)hdr, &aar);
	CHECK("arcares_parse overlong authserv_id: returns 0",    ret == 0);
	CHECK("arcares_parse overlong authserv_id: instance set", aar.instance == 1);
	CHECK("arcares_parse overlong authserv_id: value stored",
	      strlen((char *)aar.authserv_id) > 0);

	/* ------------------------------------------------------------------ */
	/* opendmarc_arcares_arc_parse: valid field                            */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_arc_parse(
	    (u_char *)"arc=pass; smtp.client-ip=1.2.3.4; arc.chain=example.com",
	    &arc_field);
	CHECK("arcares_arc_parse valid: returns 0",   ret == 0);
	CHECK("arcares_arc_parse valid: arcresult",
	      strcmp((char *)arc_field.arcresult, "pass") == 0);
	CHECK("arcares_arc_parse valid: smtpclientip",
	      strcmp((char *)arc_field.smtpclientip, "1.2.3.4") == 0);
	CHECK("arcares_arc_parse valid: arcchain",
	      strcmp((char *)arc_field.arcchain, "example.com") == 0);

	/* ------------------------------------------------------------------ */
	/* arcares_arc_parse: token with no '=' — SIGABRT regression (#222)   */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcares_arc_parse((u_char *)"noequals", &arc_field);
	CHECK("arcares_arc_parse missing '=': returns -1", ret == -1);

	/* ------------------------------------------------------------------ */
	/* arcares_arc_parse: overlong value — SIGSEGV regression (#242)      */
	/*                                                                     */
	/* After the fix the parse succeeds; value truncated to field size.    */
	/* ------------------------------------------------------------------ */

	snprintf(hdr, sizeof hdr, "arc=%s", longval);
	ret = opendmarc_arcares_arc_parse((u_char *)hdr, &arc_field);
	CHECK("arcares_arc_parse overlong value: returns 0", ret == 0);
	CHECK("arcares_arc_parse overlong value: arcresult stored",
	      strlen((char *)arc_field.arcresult) > 0);

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
	/*                                                                     */
	/* "ARC-Seal: i=1; none" style malformed headers previously triggered */
	/* assert(string != NULL) inside strip_whitespace → SIGABRT.          */
	/* ------------------------------------------------------------------ */

	ret = opendmarc_arcseal_parse((u_char *)"i=1; none", &as);
	CHECK("arcseal_parse token with no '=': returns -1", ret == -1);

	/* ------------------------------------------------------------------ */
	/* arcseal_parse: long b= value — SIGSEGV regression (#183/#236)      */
	/*                                                                     */
	/* RSA 3072-bit signatures produce ~512-byte base64 values, hitting   */
	/* the old MAX_TOKEN_LEN limit. strip_whitespace returned NULL which   */
	/* was then passed to strlcpy() → segfault.                           */
	/* After the fix the parse succeeds and the value is stored.          */
	/* ------------------------------------------------------------------ */

	snprintf(hdr, sizeof hdr,
	         "i=1; a=rsa-sha256; cv=pass; d=example.com; s=sel1; "
	         "t=1234567890; b=%s",
	         longval);
	ret = opendmarc_arcseal_parse((u_char *)hdr, &as);
	CHECK("arcseal_parse long b= (RSA 3072+): returns 0",        ret == 0);
	CHECK("arcseal_parse long b=: instance set",                 as.instance == 1);
	CHECK("arcseal_parse long b=: signature_value stored",
	      as.signature_value[0] != '\0');
	CHECK("arcseal_parse long b=: other fields preserved",
	      strcmp((char *)as.signature_domain, "example.com") == 0);

	/* ------------------------------------------------------------------ */
	/* arcseal_parse: overlong non-signature field — truncation check      */
	/* ------------------------------------------------------------------ */

	snprintf(hdr, sizeof hdr, "i=1; d=%s", longval);
	ret = opendmarc_arcseal_parse((u_char *)hdr, &as);
	CHECK("arcseal_parse overlong d= field: returns 0",      ret == 0);
	CHECK("arcseal_parse overlong d= field: instance set",   as.instance == 1);
	CHECK("arcseal_parse overlong d= field: domain stored",
	      strlen((char *)as.signature_domain) > 0);

	printf("ARC header parsing: pass=%d, fail=%d\n", pass, fail);
	return fail;
}
