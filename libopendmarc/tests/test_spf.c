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
		/* {"gushi.org",   "root@gushi.org",   "149.20.68.145",    DMARC_POLICY_SPF_OUTCOME_PASS}, */
		{"agari.com", "root@agari.com", "2001:a60:901e::22", DMARC_POLICY_SPF_OUTCOME_FAIL},
		{"agari.com", "root@agari.com", "1.2.3.4",           DMARC_POLICY_SPF_OUTCOME_FAIL},
		{"agari.com", "root@agari.com", "185.28.196.1",      DMARC_POLICY_SPF_OUTCOME_PASS},
		/* {"gushi.org",    "<>",             "204.14.152.227",   DMARC_POLICY_SPF_OUTCOME_FAIL}, */
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
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 ip4:149.20.68.145 -all",                 DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv4 */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 ip4:149.20.68.0/24 -all",                DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv4 cidr */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 ip4:149.20.69.0/24 -all",                DMARC_POLICY_SPF_OUTCOME_FAIL}, /* simple fail ipv4 cidr */
		{"2620:137:6000:10::145",   "<foo@gushi.org>", "gushi.org", "v=spf1 ip6:2620:137:6000:10::145 -all",              DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv6 compressed versus compressed */
		{"2620:137:6000:10:0:0:0:145", "<foo@gushi.org>", "gushi.org", "v=spf1 ip6:2620:137:6000:10::145 -all",              DMARC_POLICY_SPF_OUTCOME_PASS}, /* simple pass ipv6 compressed versus uncompressed */
		{"149.20.68.142",           "<foo@gushi.org>", "gushi.org", "v=spf1 mx  -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* mx check */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", NULL,                                             DMARC_POLICY_SPF_OUTCOME_PASS}, /* force a lookup */
		{"149.20.68.142",           "<>",            "gushi.org", "v=spf1 mx  -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* mx check with helo*/
		{"149.20.68.142",           "MAILER_DAEMON", "gushi.org", "v=spf1 mx  -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* mx check with helo*/
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 -ip4:1.2.3.4 ip4:149.20.68.145 -all",    DMARC_POLICY_SPF_OUTCOME_PASS}, /* '-'-qualfied ip4 not matching -> pass on matching ip4 */
		{"204.152.184.1",            "<foo@gushi.org>", "gushi.org", "v=spf1 include:isc.org  -all",      DMARC_POLICY_SPF_OUTCOME_PASS}, /* pass with include */
		{"149.20.68.145",           "<foo@sf1.gushi.org>", "sf1.gushi.org", "v=spf1 include:gushi.org       -all",      DMARC_POLICY_SPF_OUTCOME_PASS}, /* pass with include */
		{"149.30.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 include:isc.org               -all",      DMARC_POLICY_SPF_OUTCOME_FAIL}, /* fail with include */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 -a",                                      DMARC_POLICY_SPF_OUTCOME_FAIL}, /* matching a record with '-' qualifier*/
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1  a -all",                                 DMARC_POLICY_SPF_OUTCOME_PASS}, /* a record test pass */
		{"204.14.152.227",           "<foo@gushi.org>", "gushi.org", "v=spf1 -a",                                      DMARC_POLICY_SPF_OUTCOME_FAIL}, /* a record test fail */
		{"149.20.68.142",           "<foo@gushi.org>", "gushi.org", "v=spf1 a:prime.gushi.org -all",                      DMARC_POLICY_SPF_OUTCOME_PASS}, /* a record test pass */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 ptr -all",                                DMARC_POLICY_SPF_OUTCOME_PASS}, /* ptr record test pass */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 ptr:defaultsite.gushi.org -all",                        DMARC_POLICY_SPF_OUTCOME_PASS}, /* ptr record test pass */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 exists:%s -all",                          DMARC_POLICY_SPF_OUTCOME_FAIL}, /* exists bad syntax */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 exists:%{s} -all",                        DMARC_POLICY_SPF_OUTCOME_PASS}, /* exits good record */
		{"149.20.68.145",           "<foo@prime.gushi.org>", "prime.gushi.org", "v=spf1 redirect:gushi.org -all",     DMARC_POLICY_SPF_OUTCOME_FAIL}, /* redirect MUST be ignored if all is present */
		{"149.20.68.145",           "<foo@prime.gushi.org>", "prime.gushi.org", "v=spf1 redirect:gushi.org ",         DMARC_POLICY_SPF_OUTCOME_PASS}, /* pass with correctly used redirect */
		{"149.30.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 include:isc.org ip4:149.30.68.145 -all",  DMARC_POLICY_SPF_OUTCOME_PASS}, /* matching ip4 after non-matching include */
		{"149.30.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 include:isc.org -ip4:149.30.68.145 +all", DMARC_POLICY_SPF_OUTCOME_FAIL}, /* explicit fail for given IP after include */
		{"149.20.68.145",           "<foo@gushi.org>", "gushi.org", "v=spf1 -ip4:149.20.68.145 a ~all",               DMARC_POLICY_SPF_OUTCOME_FAIL}, /* fail before success */
		{NULL, NULL, NULL, NULL, 0},
	};
	SL *	sp;
	int	status;
	int	success, failures;
	int	use_mfrom;
	char	human[BUFSIZ];
	int i;

	success = failures = 0;
	for (sp = spflist, i = 0; sp->ip != NULL; ++sp, ++i)
	{
		status = opendmarc_spf_test(sp->ip, sp->mfrom, sp->helo, sp->spfrecord, FALSE, human, sizeof human, &use_mfrom);
		if (status != sp->status)
		{
			printf("Error[%d]: ip=\"%s\", mfrom=\"%s\", helo=\"%s\", spf=\"%s\", error(%d)= %s\n", i, sp->ip, sp->mfrom, sp->helo, 
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
	char *	mfrom		= "foo@gushi.org";
	char *	ip		= "149.20.68.145";
	char *	helo		= "gushi.org";
	char *	spf 		= "v=spf1 ip4:1.2.3.4 exp:http://%{s}/spf  -all";
	char *  converted	= "http://gushi.org/spf";
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
