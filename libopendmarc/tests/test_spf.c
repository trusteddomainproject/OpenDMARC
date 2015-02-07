#include "opendmarc_internal.h"
#include "dmarc.h"

#if WITH_SPF

#if HAVE_SPF2_H
// Yes we have the spf.h file, so we test libspf2
typedef struct {
	char *helo;
	char *mfrom;
	char *ip;
	int  outcome;
} SPF2_T;

int
opendmarc_spf2_run_test()
{
	SPF2_T tests[] = {
		/* {"bcx.com",   "root@bcx.com",   "204.14.152.228",    DMARC_POLICY_SPF_OUTCOME_PASS}, */
		{"agari.com", "root@agari.com", "2001:a60:901e::22", DMARC_POLICY_SPF_OUTCOME_FAIL},
		{"agari.com", "root@agari.com", "1.2.3.4",           DMARC_POLICY_SPF_OUTCOME_FAIL},
		{"agari.com", "root@agari.com", "185.28.196.1",      DMARC_POLICY_SPF_OUTCOME_PASS},
		/* {"bcx.com",    "<>",             "204.14.152.227",   DMARC_POLICY_SPF_OUTCOME_FAIL}, */
		{NULL, NULL, NULL, 0}
	};
	int		status;
	char		human[512];
	int		used_mfrom;
	int		failures = 0;
	int		success = 0;
	SPF2_T *	tpp;

	for (tpp = tests; tpp->helo != NULL; tpp++)
	{
		(void) memset(human, '\0', sizeof human);
		status = opendmarc_spf2_test(tpp->ip, tpp->mfrom, tpp->helo, NULL, FALSE, human, sizeof human, &used_mfrom);
		if (status != tpp->outcome)
		{
			printf("Error: ip=\"%s\", mfrom=\"%s\", helo=\"%s\", error(%d)= %s\n", tpp->ip, tpp->mfrom, tpp->helo, status, human);
			++failures;
		}
		else
		{
			//printf("Success: ip=\"%s\", mfrom=\"%s\", helo=\"%s\", error(%d)= %s\n", tpp->ip, tpp->mfrom, tpp->helo, status, human);
			++success;
		}
	}
	printf("Test opendmarc_spf_ip4_tests(): %d pass, %d fail\n", success, failures);
	return failures;
}

#else /* HAVE_SPF2_H */
// No spf.h so we test the internal library.

typedef struct {
	char *	ip;
	char *	mfrom;
	char * 	helo;
	char *	spfrecord;
	int	status;
} SL; 

int
opendmarc_spf_test_records(void)
{
	SL spflist[] = {
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 ip4:204.14.152.228 -all",                 DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv4 */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 ip4:204.14.152.0/24 -all",                DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv4 cidr */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 ip4:204.14.252.0/24 -all",                DMARC_POLICY_SPF_OUTCOME_FAIL}, /* simple fail ipv4 cidr */
		{"2001:a60:901e::22",        "<foo@bcx.com>", "bcx.com", "v=spf1 ip6:2001:a60:901e::22 -all",              DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv6 compressed versus compressed */
		{"2001:a60:901e:0:0:0:0:22", "<foo@bcx.com>", "bcx.com", "v=spf1 ip6:2001:a60:901e::22 -all",              DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv6 compressed versus uncompressed */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 mx  -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* mx check */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", NULL,                                             DMARC_POLICY_SPF_OUTCOME_PASS}, /* force a lookup */
		{"204.14.152.228",           "<>",            "bcx.com", "v=spf1 mx  -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* mx check with helo*/
		{"204.14.152.228",           "MAILER_DAEMON", "bcx.com", "v=spf1 mx  -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* mx check with helo*/
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 -ip4:1.2.3.4 ip4:204.14.152.228 -all",    DMARC_POLICY_SPF_OUTCOME_FAIL}, /* fail before success */
		{"174.137.46.2",             "<foo@bcx.com>", "bcx.com", "v=spf1 include:_netblocks.zdsys.com  -all",      DMARC_POLICY_SPF_OUTCOME_PASS}, /* pass with include */
		{"204.14.152.228",           "<foo@sf1.bcx.com>", "sf1.bcx.com", "v=spf1 include:bcx.com       -all",      DMARC_POLICY_SPF_OUTCOME_PASS}, /* pass with include */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 include:bcx.org               -all",      DMARC_POLICY_SPF_OUTCOME_FAIL}, /* fail with include */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 -a",                                      DMARC_POLICY_SPF_OUTCOME_PASS}, /* a record test pass */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1  a -all",                                 DMARC_POLICY_SPF_OUTCOME_PASS}, /* a record test pass */
		{"204.14.152.227",           "<foo@bcx.com>", "bcx.com", "v=spf1 -a",                                      DMARC_POLICY_SPF_OUTCOME_FAIL}, /* a record test fail */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 a:sf1.bcx.com -all",                      DMARC_POLICY_SPF_OUTCOME_PASS}, /* a record test pass */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 ptr -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* ptr record test pass */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 ptr:bcx.com -all",                        DMARC_POLICY_SPF_OUTCOME_PASS}, /* ptr record test pass */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 exists:%s -all",                          DMARC_POLICY_SPF_OUTCOME_FAIL}, /* exists bad syntax */
		{"204.14.152.228",           "<foo@bcx.com>", "bcx.com", "v=spf1 exists:%{s} -all",                        DMARC_POLICY_SPF_OUTCOME_PASS}, /* exits good record */
		{"204.14.152.228",           "<foo@sf1.bcx.com>", "sf1.bcx.com", "v=spf1 redirect:bcx.com       -all",     DMARC_POLICY_SPF_OUTCOME_PASS}, /* pass with redirect */
		{NULL, NULL, NULL, NULL, 0},
	};
	SL *	sp;
	int	status;
	int	success, failures;
	int	use_mfrom;
	char	human[BUFSIZ];

	success = failures = 0;
	for (sp = spflist; sp->ip != NULL; ++sp)
	{
		status = opendmarc_spf_test(sp->ip, sp->mfrom, sp->helo, sp->spfrecord, FALSE, human, sizeof human, &use_mfrom);
		if (status != sp->status)
		{
			printf("Error: ip=\"%s\", mfrom=\"%s\", helo=\"%s\", spf=\"%s\", error(%d)= %s\n", sp->ip, sp->mfrom, sp->helo, 
				sp->spfrecord == NULL ? "NULL" : sp->spfrecord, status, human);
			++failures;
			continue;
		}
		++success;
	}
	printf("Test opendmarc_spf_test_records(): %d pass, %d fail\n", success, failures);
	return failures;
}

int
opendmarc_spf_test_exp()
{
	SPF_CTX_T *     ctx;
	char *	mfrom		= "foo@bcx.com";
	char *	ip		= "204.14.152.228";
	char *	helo		= "bcx.com";
	char *	spf 		= "v=spf1 ip4:1.2.3.4 exp:http://%{s}/spf  -all";
	char *  converted	= "http://bcx.com/spf";
	char	errbuf[BUFSIZ];
	int	ret;
	int	success		= 0;
	int	failures	= 0;
	int	use_mfrom	= FALSE;

	ctx = opendmarc_spf_alloc_ctx();
	(void) opendmarc_spf_specify_mailfrom(ctx, mfrom, strlen(mfrom), &use_mfrom);
	(void) opendmarc_spf_specify_helo_domain(ctx, helo, strlen(helo));
	(void) opendmarc_spf_specify_ip_address(ctx, ip, strlen(ip));
	(void) opendmarc_spf_specify_record(ctx, spf, strlen(spf));

	ret = opendmarc_spf_parse(ctx, 0, errbuf, sizeof errbuf);
	if (ret != 0)
	{
		if (strcasecmp(opendmarc_spf_status_to_msg(ctx, ret), converted) == 0)
			++success;
		else
			++failures;
	}
	else
		++failures;

	ctx = opendmarc_spf_free_ctx(ctx);
	printf("Test opendmarc_spf_run_test(): %d pass, %d fail\n", success, failures);
	return failures;
}

typedef struct {
	char *connect_ip;
	char *record_ip;
	int   outcome;
} IP6LIST;

int
opendmarc_spf_ip6_tests(void)
{
	IP6LIST ip6list[] = {
		{"2001:a60:901e::22", "2001:a60:901e::22",            TRUE},
		{"2001:a60:901e::22", "2001:a60:901e:00:00:00:00:22", TRUE},
		{"2001:a60:901e::2",  "2001:a60:901e::0/126",         TRUE},
		{"2001:a60:901e::2:0",  "2001:a60:901e::0/95",         TRUE},
		{"50.57.199.2",       "50.57.199.0/27",               FALSE},
		{NULL, NULL}
	};
	IP6LIST *ipp;
	int	success, failures;

	success = failures = 0;
	for (ipp = ip6list; ipp->connect_ip != NULL; ++ipp)
	{
		if (opendmarc_spf_ipv6_cidr_check(ipp->connect_ip, ipp->record_ip) != ipp->outcome)
		{
			printf("Error: %s compared to %s failed\n", ipp->connect_ip, ipp->record_ip);
			++failures; 
			continue;
		}
		++success;
	}
	printf("Test opendmarc_spf_ip6_tests(): %d pass, %d fail\n", success, failures);
	return failures;
	return 0;
}

typedef struct {
	char *connect_ip;
	char *record_ip;
	int   outcome;
} IP4LIST;

int
opendmarc_spf_ip4_tests(void)
{
	IP4LIST ip4list[] = {
		{"50.57.199.2",       "50.57.199.0/27", TRUE},
		{"51.57.199.2",       "50.57.199.0/27", FALSE},
		{NULL, NULL}
	};
	IP4LIST *ipp;
	int	success, failures;
	u_long  ip;

	success = failures = 0;
	for (ipp = ip4list; ipp->connect_ip != NULL; ++ipp)
	{
		ip = inet_addr(ipp->connect_ip);
		ip = htonl(ip);
		if (opendmarc_spf_cidr_address(ip, ipp->record_ip) != ipp->outcome)
		{
			printf("Error: %s compared to %s failed\n", ipp->connect_ip, ipp->record_ip);
			++failures; 
			continue;
		}
		++success;
	}
	printf("Test opendmarc_spf_ip4_tests(): %d pass, %d fail\n", success, failures);
	return failures;
}
#endif /* HAVE_SPF2_H */

int
main(int argc, char **argv)
{

#if HAVE_SPF2_H
	if (opendmarc_spf2_run_test() != 0)
#else /* HAVE_SPF2_H */
	if (opendmarc_spf_ip6_tests() != 0 || opendmarc_spf_ip4_tests() != 0 || opendmarc_spf_test_records() != 0 || opendmarc_spf_test_exp() != 0)
#endif /* HAVE_SPF2_H */
		return 1;
	return 0;
}

#endif /* WITH_SPF */
