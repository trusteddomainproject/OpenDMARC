/*
**  Copyright (c) 2025, The Trusted Domain Project.
**    All rights reserved.
**
**  Unit tests for ARC-Authentication-Results and ARC-Seal header parsing.
**  Covers normal operation and overlong-token crash paths (issues #241, #242).
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

/*
**  Builds a string of 'c' repeated 'n' times into buf (which must be n+1 bytes).
*/
static void
repeat_char(char *buf, char c, size_t n)
{
	memset(buf, c, n);
	buf[n] = '\0';
}

int
main(int argc, char **argv)
{
	struct arcares     aar;
	struct arcares_arc_field arc_field;
	struct arcseal     as;
	char               longval[520 + 1];
	char               hdr[4200];
	int                ret;

	repeat_char(longval, 'a', 520);

	/* --- opendmarc_arcares_parse: valid header --- */

	ret = opendmarc_arcares_parse(
	    (u_char *)"i=1; example.com; arc=pass; "
	              "dmarc=pass header.from=example.com; "
	              "dkim=pass header.d=example.com; "
	              "spf=pass smtp.mailfrom=example.com",
	    &aar);
	CHECK("arcares_parse valid: returns 0",       ret == 0);
	CHECK("arcares_parse valid: instance == 1",   aar.instance == 1);
	CHECK("arcares_parse valid: authserv_id",
	      strcmp((char *)aar.authserv_id, "example.com") == 0);

	/* --- opendmarc_arcares_parse: overlong authserv_id (issue #242) ---
	**
	**  strip_whitespace() returns NULL when the token is >= 512 chars.
	**  Before the fix this caused a NULL dereference in strlcpy(); after
	**  the fix it should return -1 cleanly.
	*/

	snprintf(hdr, sizeof hdr, "i=1; %s; arc=pass", longval);
	ret = opendmarc_arcares_parse((u_char *)hdr, &aar);
	CHECK("arcares_parse overlong authserv_id: returns -1", ret == -1);

	/* --- opendmarc_arcares_arc_parse: valid field --- */

	ret = opendmarc_arcares_arc_parse(
	    (u_char *)"arc=pass; smtp.client-ip=1.2.3.4; arc.chain=example.com",
	    &arc_field);
	CHECK("arcares_arc_parse valid: returns 0",         ret == 0);
	CHECK("arcares_arc_parse valid: arcresult",
	      strcmp((char *)arc_field.arcresult, "pass") == 0);
	CHECK("arcares_arc_parse valid: smtpclientip",
	      strcmp((char *)arc_field.smtpclientip, "1.2.3.4") == 0);
	CHECK("arcares_arc_parse valid: arcchain",
	      strcmp((char *)arc_field.arcchain, "example.com") == 0);

	/* --- opendmarc_arcares_arc_parse: overlong value (issue #242) --- */

	snprintf(hdr, sizeof hdr, "arc=%s", longval);
	ret = opendmarc_arcares_arc_parse((u_char *)hdr, &arc_field);
	CHECK("arcares_arc_parse overlong value: returns -1", ret == -1);

	/* --- opendmarc_arcseal_parse: valid header --- */

	ret = opendmarc_arcseal_parse(
	    (u_char *)"i=1; a=rsa-sha256; cv=pass; d=example.com; "
	              "s=sel1; t=1234567890; b=abc123",
	    &as);
	CHECK("arcseal_parse valid: returns 0",    ret == 0);
	CHECK("arcseal_parse valid: instance == 1", as.instance == 1);
	CHECK("arcseal_parse valid: domain",
	      strcmp((char *)as.signature_domain, "example.com") == 0);
	CHECK("arcseal_parse valid: selector",
	      strcmp((char *)as.signature_selector, "sel1") == 0);
	CHECK("arcseal_parse valid: cv",
	      strcmp((char *)as.chain_validation, "pass") == 0);

	/* --- opendmarc_arcseal_parse: overlong value (issue #241/#242 pattern) --- */

	snprintf(hdr, sizeof hdr, "i=1; d=%s", longval);
	ret = opendmarc_arcseal_parse((u_char *)hdr, &as);
	CHECK("arcseal_parse overlong value: returns -1", ret == -1);

	printf("ARC header parsing: pass=%d, fail=%d\n", pass, fail);
	return fail;
}
