#include "../opendmarc_internal.h"
#include "../dmarc.h"

#define TESTFILE "testfiles/effective_tld_names.dat"

int
main(int argc, char **argv)
{
	static char *record=	"v=DMARC1; p=none; sp=none; adkim=s; aspf=s; pct=50; t=y; ri=300; rf=afrf; rua=mailto:dmarc-a@abuse.net; ruf=mailto:dmarc-f@abuse.net";
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;
	int pass, fails, count;
	int pct;
	int adkim;
	int aspf;
	int t;
	
	pass = fails = count = 0;
	pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
	if (pctx == NULL)
	{
		(void) fprintf(stderr, "opendmarc_policy_connect_init: %s\n", strerror(errno));
		return 1;
	}
	status = opendmarc_policy_parse_dmarc(pctx, (u_char *)"abuse.net", (u_char *)record);
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
	status = opendmarc_policy_fetch_t(pctx, &t);
	if (status != DMARC_PARSE_OKAY)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_t: %s: FAIL\n", __FILE__, __LINE__, opendmarc_policy_status_to_str(status));
		fails += 1;
	}
	if (t != DMARC_RECORD_T_Y)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_t: expected %d got %d: FAIL\n", __FILE__, __LINE__,  DMARC_RECORD_T_Y, t);
		fails += 1;
	}

	/*
	** Regression tests for issue #256: opendmarc_policy_fetch_ruf() and
	** opendmarc_policy_fetch_rua() used || instead of && when checking
	** whether to call memset(), so passing NULL with a non-zero size would
	** call memset(NULL, ...) and segfault.
	*/

	/* NULL buf + zero size: normal call pattern, must not crash */
	count++;
	if (opendmarc_policy_fetch_ruf(pctx, NULL, 0, 1) == NULL)
	{
		printf("\t%s(%d): fetch_ruf(NULL, 0): FAIL\n", __FILE__, __LINE__);
		fails += 1;
	}

	/* NULL buf + non-zero size: the crash case before the fix */
	count++;
	(void) opendmarc_policy_fetch_ruf(pctx, NULL, 256, 1);
	/* reaching here without crashing is the pass condition */

	/* valid buf: confirm ruf list is returned */
	count++;
	{
		u_char buf[256];
		u_char **ret = opendmarc_policy_fetch_ruf(pctx, buf, sizeof buf, 1);
		if (ret == NULL)
		{
			printf("\t%s(%d): fetch_ruf with valid buf returned NULL: FAIL\n", __FILE__, __LINE__);
			fails += 1;
		}
	}

	/* Same three cases for fetch_rua */
	count++;
	if (opendmarc_policy_fetch_rua(pctx, NULL, 0, 1) == NULL)
	{
		printf("\t%s(%d): fetch_rua(NULL, 0): FAIL\n", __FILE__, __LINE__);
		fails += 1;
	}

	count++;
	(void) opendmarc_policy_fetch_rua(pctx, NULL, 256, 1);

	count++;
	{
		u_char buf[256];
		u_char **ret = opendmarc_policy_fetch_rua(pctx, buf, sizeof buf, 1);
		if (ret == NULL)
		{
			printf("\t%s(%d): fetch_rua with valid buf returned NULL: FAIL\n", __FILE__, __LINE__);
			fails += 1;
		}
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/* RFC 9989: t= absent defaults to "n" behavior (DMARC_RECORD_T_UNSPECIFIED) */
	count++;
	pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
	if (pctx == NULL)
	{
		(void) fprintf(stderr, "opendmarc_policy_connect_init: %s\n", strerror(errno));
		return 1;
	}
	status = opendmarc_policy_parse_dmarc(pctx, (u_char *)"abuse.net",
	                                       (u_char *)"v=DMARC1; p=reject;");
	if (status != DMARC_PARSE_OKAY)
	{
		printf("\t%s(%d): opendmarc_policy_parse_dmarc: %s: FAIL\n", __FILE__, __LINE__, opendmarc_policy_status_to_str(status));
		fails += 1;
	}
	status = opendmarc_policy_fetch_t(pctx, &t);
	if (status != DMARC_PARSE_OKAY || t != DMARC_RECORD_T_UNSPECIFIED)
	{
		printf("\t%s(%d): opendmarc_policy_fetch_t: expected unspecified, got %d: FAIL\n", __FILE__, __LINE__, t);
		fails += 1;
	}
	pctx = opendmarc_policy_connect_shutdown(pctx);

	return fails;
}
