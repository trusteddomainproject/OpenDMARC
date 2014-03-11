#include "../opendmarc_internal.h"
#include "../dmarc.h"

#define TESTFILE "testfiles/effective_tld_names.dat"
typedef struct {
	char *	subdomain;
	char *	tld;
	int	mode;
	int  	outcome;
} TEST_ALIGNMENT_T;

int
main(int argc, char **argv)
{
	TEST_ALIGNMENT_T *alignp;
	TEST_ALIGNMENT_T alignm_test[] = {
		/* 1 */ {"a.b.c.bcx.com",	"bcx.com",	DMARC_RECORD_A_RELAXED,	 0},
		/* 2 */ {"a.b.c.edu.ar",	"edr.au",	DMARC_RECORD_A_STRICT,	-1},
		/* 3 */ {"oooo.com",		"ooo.com",	DMARC_RECORD_A_STRICT,	-1},
		/* 4 */ {"a.foo.com",           "b.foo.com",	DMARC_RECORD_A_RELAXED,	 0},
		/* 5 */ {".mac.com.",           "mac.com",	DMARC_RECORD_A_STRICT,	 0},
		/* 6 */ {"....mac.com....",     "mac.com",	DMARC_RECORD_A_STRICT,	 0},
		/* 7 */ {"mac...com",           "..com",	DMARC_RECORD_A_STRICT,	-1},
		/* 8 */ {"a.b.com",             "b.com",	DMARC_RECORD_A_RELAXED,	 0},
		/* 9 */ {"b.com",               "a.b.com",	DMARC_RECORD_A_RELAXED,	 0},
		/* 10 */ {"a.b.de",             "a.b.de",	DMARC_RECORD_A_STRICT,	 0},
			{NULL, NULL, 0},
	};
	int	outcome;
	int	pass, fails, count;
	char *	srcdir;
	
	srcdir = getenv("srcdir");
	if (srcdir != NULL)
	{
		if (chdir(srcdir) != 0)
		{
			perror(srcdir);
			return 1;
		}
	}

	pass = fails = count = 0;
	/*
	 * First without a tld file.
	 */
	for (alignp = alignm_test; alignp != NULL && alignp->subdomain != NULL; ++alignp)
	{
		count += 1;
		outcome = opendmarc_policy_check_alignment(alignp->subdomain, alignp->tld, alignp->mode);
		if (outcome == alignp->outcome)
		{
			//printf("\tALIGNMENT No TLD file: find test: %d: PASS\n", count);
			pass += 1;
		}
		else
		{
			printf("\tALIGNMENT No TLD file: domain=%s versus tld=%s relaxed test No. %d: FAIL\n", alignp->subdomain, alignp->tld, count);
			fails += 1;
		}
	}
	/*
	 * Second with a tld file.
	 */
	if (opendmarc_tld_read_file(TESTFILE, "//", "*.", "!") != 0)
	{
		printf("\tTLD find test: %s: could not read. Skipping\n", TESTFILE);
		return 0;
	}
	count = 0;
	for (alignp = alignm_test; alignp != NULL && alignp->subdomain != NULL; ++alignp)
	{
		count += 1;
		outcome = opendmarc_policy_check_alignment(alignp->subdomain, alignp->tld, alignp->mode);
		if (outcome == alignp->outcome)
		{
			//printf("\tALIGNMENT With TLD file: find test: %d: PASS\n", count);
			pass += 1;
		}
		else
		{
			printf("\tALIGNMENT No With file: find test: %d: FAIL\n", count);
			fails += 1;
		}
	}
	printf("ALIGNMENT find test: pass=%d, fail=%d\n", pass, fails);
	return fails;
}
