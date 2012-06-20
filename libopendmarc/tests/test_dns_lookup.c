#include "../opendmarc_internal.h"

typedef struct {
	char *	domain;
	int	cpnotnull;
	int 	replyzero;
	char *	what;
} DL; 

int
dmarc_dns_test_record(void)
{
	DL domain_list[] = {
		{"_dmarc.bcx.com", TRUE, TRUE, "DMARC record found"},
		{"bcx.org._report._dmarc.bcx.com", TRUE, TRUE, "DMARC _report record found"},
		{"_dmarc.mail.bcx.com", FALSE, FALSE, "Existing domain, no DMARC"},
		{"_dmarc.none.bcx.com",	FALSE, FALSE, "No such domain"},
		{NULL, 0, 0, NULL},
	};
	DL *	dp;
	char 	txt_record[2048];
	int	reply;
	char *	cp;
	int	success, failures;

	success = failures = 0;
	for (dp = domain_list; dp->domain != NULL; ++dp)
	{
		cp = dmarc_dns_get_record(dp->domain, &reply, txt_record, sizeof txt_record);
		if (cp == NULL)
		{
			if (dp->cpnotnull == TRUE) /* cp should be != NULL */
			{
				printf("\t%s(%d): %s: %s: FAIL.\n", __FILE__, __LINE__, dp->domain, dp->what);
				++failures;
				continue;
			}
			if (reply != 0 && dp->replyzero == TRUE)
			{
				printf("\t%s(%d): %s: %s: FAIL.\n",
						__FILE__, __LINE__, dp->domain, dp->what);
				++failures;
				continue;
			}
			//printf("\t%s(%d): %s: %s: PASS.\n", __FILE__, __LINE__, dp->domain, dp->what);
			++success;
		}
		else
		{
			if (dp->cpnotnull == FALSE) /* cp should be == NULL */
			{
				printf("\t%s(%d): %s: %s: FAIL.\n",
						__FILE__, __LINE__, dp->domain, dp->what);
				++failures;
				continue;
			}
			if (reply == 0 && dp->replyzero == FALSE)
			{
				printf("\t%s(%d): %s: %s: FAIL.\n",
						__FILE__, __LINE__, dp->domain, dp->what);
				++failures;
				continue;
			}
			//printf("\t%s(%d): %s: %s: PASS.\n", __FILE__, __LINE__, dp->domain, dp->what);
			++success;
		}

	}
	printf("DNS Lookup _dmarc Records: %d pass, %d fail\n", success, failures);
	return failures;
}


int
main(int argc, char **argv)
{
	if (dmarc_dns_test_record() != 0)
		return 1;
	return 0;
}
