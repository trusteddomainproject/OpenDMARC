#include "../opendmarc_internal.h"
#include "../dmarc.h"

#define TESTFILE "testfiles/effective_tld_names.dat"

int
main(int argc, char **argv)
{
	static char *record=	"v=DMARC1; p=none; sp=none; adkim=s; aspf=s; pct=50; ri=300; rf=afrf; rua=mailto:dmarc-a@abuse.net; ruf=mailto:dmarc-f@abuse.net";
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;
	int pass, fails, count;
	int pct;
	int adkim;
	int aspf;
	
	pass = fails = count = 0;
	pctx = opendmarc_policy_connect_init("1.2.3.4", 0);
	if (pctx == NULL)
	{
		(void) fprintf(stderr, "opendmarc_policy_connect_init: %s\n", strerror(errno));
		return 1;
	}
	status = opendmarc_policy_parse_dmarc(pctx, "abuse.net", record);
	if (status != DMARC_PARSE_OKAY)
	{
		printf("\t%s(%d): opendmarc_policy_parse_dmarc: %s: FAIL\n", __FILE__, __LINE__, opendmarc_policy_status_to_str(status));
		fails += 1;
	}
	status = opendmarc_policy_fetch_pct(pctx, &pct);
	if (status != DMARC_PARSE_OKAY)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_pct: %s: FAIL\n", __FILE__, __LINE__, opendmarc_policy_status_to_str(status));
		fails += 1;
	}
	if (pct != 50)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_pct: expected 50 got %d: FAIL\n", __FILE__, __LINE__,  pct);
		fails += 1;
	}
	status = opendmarc_policy_fetch_adkim(pctx, &adkim);
	if (status != DMARC_PARSE_OKAY)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_adkim: %s: FAIL\n", __FILE__, __LINE__, opendmarc_policy_status_to_str(status));
		fails += 1;
	}
	if (adkim != DMARC_RECORD_A_STRICT)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_adkim: expected %d got %d: FAIL\n", __FILE__, __LINE__,  DMARC_RECORD_A_STRICT, adkim);
		fails += 1;
	}
	status = opendmarc_policy_fetch_aspf(pctx, &aspf);
	if (status != DMARC_PARSE_OKAY)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_aspf: %s: FAIL\n", __FILE__, __LINE__, opendmarc_policy_status_to_str(status));
		fails += 1;
	}
	if (aspf != DMARC_RECORD_A_STRICT)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_adkim: expected %d got %d: FAIL\n", __FILE__, __LINE__,  DMARC_RECORD_A_STRICT, aspf);
		fails += 1;
	}
	return fails;
}
