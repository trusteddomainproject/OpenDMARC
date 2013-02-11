#include "../opendmarc_internal.h"
#ifndef OPENDMARC_POLICY_C
# define OPENDMARC_POLICY_C
#endif /* ! OPENDMARC_POLICY_C */
#include "../dmarc.h"

#define TESTFILE "testfiles/effective_tld_names.dat"

typedef struct {
	char *dmarc;
	int   outcome;
} TEST_DMARC_PARSE_T;

int
main(int argc, char **argv)
{
	TEST_DMARC_PARSE_T *dpp;
	TEST_DMARC_PARSE_T dpp_test[] = {
		/* 1  */  {"v=DMARC1; p=none; rf=afrf; rua=mailto:dmarc-a@abuse.net; ruf=mailto:dmarc-f@abuse.net", DMARC_PARSE_OKAY},
		/* 2  */ {"v=DMARC1; p=none;", DMARC_PARSE_OKAY},
		/* 3  */ {"v=DMARC1; p=reject;", DMARC_PARSE_OKAY},
		/* 4  */ {"v=DMARC1; p=quarantine;", DMARC_PARSE_OKAY},
		/* 5  */ {"v=DMARC1; p=n;", DMARC_PARSE_OKAY},
		/* 6  */ {"", DMARC_PARSE_ERROR_EMPTY},
		/* 7  */ {"V=BOB", DMARC_PARSE_ERROR_BAD_VERSION},
		/* 8  */ {"v=DMARC1; p=bob;", DMARC_PARSE_ERROR_BAD_VALUE},
		/* 9  */ {"v=DMARC1; p=none; sp=bob;", DMARC_PARSE_ERROR_BAD_VALUE},
		/* 10 */ {"v=DMARC1; p=none; adkim=bob;", DMARC_PARSE_ERROR_BAD_VALUE},
		/* 11 */ {"v=DMARC1; p=none; aspf=bob;", DMARC_PARSE_ERROR_BAD_VALUE},
		/* 12 */ {"v=DMARC1; p=none; rf=bob;", DMARC_PARSE_ERROR_BAD_VALUE},
		/* 13 */ {"v=DMARC1; p=none; ri=bob;", DMARC_PARSE_ERROR_BAD_VALUE},
		/* 14 */ {"v=DMARC1; p=none; pct=500;", DMARC_PARSE_ERROR_BAD_VALUE},
		/* 15 */ {"v=DMARC1; pct=100;", DMARC_PARSE_ERROR_NO_REQUIRED_P},
		/* 16 */ {"v=DMARC1; p=none; rua=ftp://abuse.com", DMARC_PARSE_OKAY},
		/* 17 */ {"v=DMARC1; p=none; ruf=mailto://abuse.com", DMARC_PARSE_OKAY},
		/* 18 */ {"v=DMARC1; p=none; ruf=mailto://abuse.com; foo=bar; buzz=happy;", DMARC_PARSE_OKAY},
			{NULL, 0},
	};
	int	pass, fails, count;
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;
	
	pass = fails = count = 0;
	for (dpp = dpp_test; dpp != NULL && dpp->dmarc != NULL; ++dpp)
	{
		count += 1;
		pctx = opendmarc_policy_connect_init("1.2.3.4", 0);
		if (pctx == NULL)
		{
			(void) fprintf(stderr, "opendmarc_policy_connect_init: %s\n", strerror(errno));
			return 1;
		}
		status = opendmarc_policy_parse_dmarc(pctx, "abuse.net", dpp->dmarc);
		if (status == dpp->outcome)
		{
			//printf("\tDMARC Policy Parse: %d: PASS\n", count);
			pass += 1;
		}
		else
		{
			printf("\tDMARC Policy Parse: %d: \"%s\", status=%d  FAIL\n", count, dpp->dmarc, status);
			fails += 1;
		}
		pctx = opendmarc_policy_connect_shutdown(pctx);
	}
	printf("DMARC Policy Parse: pass=%d, fail=%d\n", pass, fails);
	return fails;
}
