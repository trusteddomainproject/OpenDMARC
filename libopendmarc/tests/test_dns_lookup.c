#include "../opendmarc_internal.h"

int
main(int argc, char **argv)
{
	if (dmarc_dns_test_record() != 0)
		return 1;
	return 0;
}
