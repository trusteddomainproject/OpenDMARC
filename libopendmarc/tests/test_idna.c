#include "../opendmarc_internal.h"
#include "../dmarc.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
#ifdef HAVE_LIBIDN2
	struct
	{
		const char *input;
		const char *want;
	} cases[] =
	{
		{ "m\xc3\xbcnchen.example.com", "xn--mnchen-3ya.example.com" },
		{ "example\xef\xbc\x8e" "com", "example.com" },
		{ "example\xe3\x80\x82" "com", "example.com" },
		{ "EXAMPLE.COM", "example.com" }
	};
	unsigned int c;
	int fails = 0;

	for (c = 0; c < sizeof cases / sizeof cases[0]; c++)
	{
		DMARC_POLICY_T *pctx;
		u_char buf[256];

		pctx = opendmarc_policy_connect_init("1.2.3.4", 0);
		if (pctx == NULL)
		{
			fprintf(stderr, "test_idna: connect_init failed\n");
			return 1;
		}

		if (opendmarc_policy_store_from_domain(pctx,
		                                       (u_char *) cases[c].input)
		    != DMARC_PARSE_OKAY)
		{
			fprintf(stderr, "test_idna: store_from_domain(%s) failed\n",
			        cases[c].input);
			fails++;
			continue;
		}

		(void) memset(buf, '\0', sizeof buf);
		if (opendmarc_policy_fetch_from_domain(pctx, buf, sizeof buf)
		    != DMARC_PARSE_OKAY)
		{
			fprintf(stderr, "test_idna: fetch_from_domain(%s) failed\n",
			        cases[c].input);
			fails++;
			continue;
		}

		if (strcmp((char *) buf, cases[c].want) != 0)
		{
			fprintf(stderr,
			        "test_idna: %s -> %s, expected %s\n",
			        cases[c].input, (char *) buf, cases[c].want);
			fails++;
		}
	}

	printf("test_idna: %d failure(s)\n", fails);
	return fails;
#else /* HAVE_LIBIDN2 */
	(void) argc;
	(void) argv;
	printf("test_idna: SKIPPED (libidn2 not available)\n");
	return 0;
#endif /* HAVE_LIBIDN2 */
}
