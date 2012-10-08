#include "../opendmarc_internal.h"

typedef struct {
	char *raw;
	char *should_get;
} TEST_FINEDDOMAIN_T;

int
main(int argc, char **argv)
{
	TEST_FINEDDOMAIN_T *domp;
	TEST_FINEDDOMAIN_T domain_test[] = {
		/* 1 */  {"Joe Johnson <joe@joe.com>", "joe.com"},
		/* 2 */  {"\"Johnson, Joe <joe@joe.com>\" joe@joe.com", "joe.com"},
		/* 3 */  {"\"Joe Johnson\" <joe@joe.com>", "joe.com"},
		/* 4 */  {"(Joe Johnson) joe@joe.com", "joe.com"},
		/* 5 */  {"joe@joe.com", "joe.com"},
		/* 6 */  {"<<<><joe@joe.com>>>", "joe.com"},
		/* 7 */  {"Joe Johnson <joe@joe.com>, ace@ace.com", "joe.com"},
		/* 8 */  {"joe@joe.com, ace@ace.com", "joe.com"},
		/* 9 */  {"Mail From:<joe@joe.com>", "joe.com"},
		/* 10 */ {"\"Mandel, Bob\" <joe@joe.com>", "joe.com"},
		/* 11 */ {"(,) joe@joe.com", "joe.com"},
		/* 12 */ {"\"( bob@bob.com)\" joe@joe.com", "joe.com"},
		/* 12 */ {"From: Davide D'Marco <user@blah.com>", "blah.com"},
			 {NULL, NULL},
	};
	u_char dbuf[256];
	int	pass, fails, count;
	u_char	*dp;
	
	pass = fails = count = 0;
	for (domp = domain_test; domp != NULL && domp->raw != NULL; ++domp)
	{
		count += 1;
		dp = opendmarc_util_finddomain(domp->raw, dbuf, sizeof dbuf);
		if (dp == NULL)
		{
			(void) printf("\t%s: %s\n", domp->raw, strerror(errno));
			++fails;
			continue;
		}
		if (strcmp(dbuf, domp->should_get) == 0)
		{
			//printf("\tFinddomain test: %d: PASS\n", count);
			pass += 1;
		}
		else
		{
			printf("\tFinddomain test: %d: FAIL\n", count);
			fails += 1;
		}
	}
	printf("Finddomain test: pass=%d, fail=%d\n", pass, fails);
	return fails;
}
