#include "../opendmarc_internal.h"
#include "../dmarc.h"

#define TESTFILE "testfiles/effective_tld_names.dat"

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
		{"web.de", FALSE, FALSE, "Existing domain, no DMARC"},
		/* {"_dmarc.sf1.i.bcx.com", TRUE, TRUE, "Got DMARC record via CNAME"}, */
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
	printf("Test dmarc_dns_get_record(): %d pass, %d fail\n", success, failures);
	return failures;
}

typedef struct {
	char *	domain;
	int	use_tld_list;
	int 	status;
} DL2; 

int
dmarc_dns_test_query(void)
{
	DL2 domain_list[] = {
		{"linkedin.com",FALSE, 	0},
		{"mail.bcx.com",FALSE, 	DMARC_DNS_ERROR_NO_RECORD},
		{"none.bcx.com",FALSE, 	DMARC_DNS_ERROR_NO_RECORD},
		{"web.de",	FALSE, 	DMARC_DNS_ERROR_NO_RECORD},
		{"service3.zalando-lounge.de", FALSE, DMARC_PARSE_OKAY},
		{"service3.zalando-lounge.de", TRUE, DMARC_PARSE_OKAY},
		{NULL, 0},
	};
	DL2 *	dp;
	int	success, failures;
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;

	success = failures = 0;
	for (dp = domain_list; dp->domain != NULL; ++dp)
	{
		pctx = opendmarc_policy_connect_init("0.0.0.0", FALSE);
		if (dp->use_tld_list)
			(void) opendmarc_tld_read_file(TESTFILE, "//", "*.", "!");
		status = opendmarc_policy_query_dmarc(pctx, dp->domain);
		pctx = opendmarc_policy_connect_shutdown(pctx);
		if (status != dp->status)
		{
			printf("\t%s(%d): %s: %d: FAIL.\n", __FILE__, __LINE__, dp->domain, status);
			++failures;
			continue;
		}
		//printf("\t%s(%d): %s: %d: PASS.\n", __FILE__, __LINE__, dp->domain, status);
		++success;
	}
	printf("Test opendmarc_policy_query_dmarc(): %d pass, %d fail\n", success, failures);
	return failures;
}

int
main(int argc, char **argv)
{
	if (dmarc_dns_test_record() != 0)
		return 1;
	if (dmarc_dns_test_query() != 0)
		return 1;
	return 0;
}
