#include "../opendmarc_internal.h"

#define TESTFILE "testfiles/effective_tld_names.dat"

typedef struct {
	char *domain;
	char *tld;
} TEST_TLD_T;

int
main(int argc, char **argv)
{
	TEST_TLD_T tld_test[] = {
		{"a.b.c.bcx.com", "bcx.com"},				/* *.com */
		{"a.b.c.educ.ar", "educ.ar"},				/* !educ.ar */
		{"a.b.c.xn--mgba3a4f16a.ir", "c.xn--mgba3a4f16a.ir"},
		{"a.b.c.\0xd8\0xa7\0x85\0xd8\0xa7\0xd8\0xb1\0xd8\0xa7\0xd8\0xaa", "c.\0xd8\0xa7\0x85\0xd8\0xa7\0xd8\0xb1\0xd8\0xa7\0xd8\0xaa"},
		{NULL, NULL},
	};
	
	(void) opendmarc_tld_read_file(TESTFILE, "//", "*.", "!");

	return 0;
}
