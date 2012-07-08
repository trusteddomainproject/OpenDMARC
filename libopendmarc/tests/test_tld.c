#include "../opendmarc_internal.h"

#define TESTFILE "testfiles/effective_tld_names.dat"

typedef struct {
	char *domain;
	char *tld;
} TEST_TLD_T;

int
main(int argc, char **argv)
{
	TEST_TLD_T *tldp;
	TEST_TLD_T tld_test[] = {
		/* 1 */ {"a.b.c.bcx.com", "bcx.com"},				/* *.com */
		/* 2 */ {"a.b.c.educ.ar", "educ.ar"},				/* !educ.ar */
		/* 3 */ {"a.b.c.xn--mgba3a4f16a.ir", "c.xn--mgba3a4f16a.ir"},
		/* 4 */ {"a.b.c.\0xd8\0xa7\0xdb\0x8c\0xd8\0xb1\0xd8\0xa7\0xd9\0x86.ar", "c.\0xd8\0xa7\0xdb\0x8c\0xd8\0xb1\0xd8\0xa7\0xd9\0x86.ar"},
			{NULL, NULL},
	};
	u_char tldbuf[256];
	int	pass, fails, count;
	
	if (opendmarc_tld_read_file(TESTFILE, "//", "*.", "!") != 0)
	{
		printf("\tTLD find test: %s: could not read. Skipping\n", TESTFILE);
		return 0;
	}
	pass = fails = count = 0;
	for (tldp = tld_test; tldp != NULL && tldp->domain != NULL; ++tldp)
	{
		count += 1;
		(void) opendmarc_get_tld(tldp->domain, tldbuf, sizeof tldbuf);
		if (memcmp(tldp->tld, tldbuf, strlen(tldp->tld)) == 0)
		{
			//printf("\tTLD find test: %d: PASS\n", count);
			pass += 1;
		}
		else
		{
			printf("\tTLD find test: %d: FAIL\n", count);
			fails += 1;
		}
	}
	printf("TLD find test: pass=%d, fail=%d\n", pass, fails);
	return fails;
}
