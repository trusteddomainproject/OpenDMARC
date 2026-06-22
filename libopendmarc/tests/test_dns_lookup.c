/*
** test_dns_lookup.c -- live DNS tests for the low-level DMARC/xdomain lookups
**
** This file was disabled (commented out of check_PROGRAMS) in 2015 because
** every case here depended on third-party domains (bcx.com, linkedin.com,
** facebook.com, web.de, csh.rit.edu, zalando-lounge.de) that nobody on this
** project controls, so the test broke whenever one of those domains' DNS
** changed.  It has been rewritten against domains Dan Mahoney controls
** (gushi.org, and the dmarcwalk.gushi.org fixture zone) plus the
** RFC 2606 ".invalid" TLD, which is reserved to never resolve, for the
** "this absolutely does not exist" cases.
**
** Notes on specific fixtures used below:
**   - gushi.org has a real "v=DMARC1" record at its apex, and a wildcard
**     "*._report._dmarc.gushi.org" record that authorizes ANY domain to
**     send it cross-domain DMARC reports -- that wildcard is what makes
**     the xdomain-authorization-exists case below work without needing a
**     second, independently controlled domain.
**   - defaultsite.gushi.org is a real host (has an A record) with no
**     _dmarc record of its own, standing in for "existing domain, no
**     DMARC record" the way web.de/mail.bcx.com used to.
**   - sub.nopsd.dmarcwalk.gushi.org has no record of its own, but its
**     parent nopsd.dmarcwalk.gushi.org does; see the "dmarcwalk" section
**     of testfiles/test-dns.zone.inc for the full fixture layout (the
**     gushi.org-specific apex records used elsewhere in this file are in
**     testfiles/gushi.org.zone.inc instead).
*/

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
		{"_dmarc.gushi.org", TRUE, TRUE, "DMARC record found"},
		{"dmarcwalk.gushi.org._report._dmarc.gushi.org", TRUE, TRUE, "DMARC _report record found"},
		{"_dmarc.defaultsite.gushi.org", FALSE, FALSE, "Existing domain, no DMARC"},
		{"*._report._dmarc.gushi.org", TRUE, TRUE, "DMARC record found"},
		{"_dmarc.nosuchhost.gushi.org", FALSE, FALSE, "No such domain"},
		{"gushi.org", FALSE, FALSE, "Existing domain, no DMARC"},
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
		{"gushi.org",			FALSE,	0},
		{"sub.nopsd.dmarcwalk.gushi.org", FALSE, DMARC_PARSE_OKAY},
		{"none.test.invalid",		FALSE,	DMARC_DNS_ERROR_NO_RECORD},
		{"sub.nopsd.dmarcwalk.gushi.org", TRUE,  DMARC_PARSE_OKAY},
		{"none.test.invalid",		TRUE,	DMARC_DNS_ERROR_NO_RECORD},
		{NULL, 0},
	};
	DL2 *	dp;
	int	success, failures;
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;

	success = failures = 0;
	for (dp = domain_list; dp->domain != NULL; ++dp)
	{
		pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
		if (dp->use_tld_list)
			(void) opendmarc_tld_read_file(TESTFILE, "//", "*.", "!");
		status = opendmarc_policy_query_dmarc(pctx, (u_char *)dp->domain);
		pctx = opendmarc_policy_connect_shutdown(pctx);
		if (status != dp->status)
		{
			printf("\t%s(%d): %s: status=%d, sought_status=%d: FAIL.\n", __FILE__, __LINE__, dp->domain, status, dp->status);
			++failures;
			continue;
		}
		//printf("\t%s(%d): %s: status=%d, sought_status=%d: PASS.\n", __FILE__, __LINE__, dp->domain, status, dp->status);
		++success;
	}
	printf("Test opendmarc_policy_query_dmarc(): %d pass, %d fail\n", success, failures);
	return failures;
}

typedef struct {
	char * domain;
	char * uri;
	int status;
} DL3;

int
dmarc_dns_test_xdomain_query(void)
{
	DL3 domain_list[] = {
		{"gushi.org",			"postmaster@gushi.org",		DMARC_PARSE_OKAY},
		{"dmarcwalk.gushi.org",		"postmaster@gushi.org",		DMARC_PARSE_OKAY},
		{"gushi.org",			"postmaster@dmarcwalk.gushi.org",	DMARC_DNS_ERROR_NO_RECORD},
		{"gushi.org",			"worr@nosuchdomain.test.invalid",	DMARC_DNS_ERROR_NO_RECORD},
		{NULL, NULL, 0},
	};

	DL3 *dp;
	int successes, failures;
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;

	/*
	 * dmarc_dns_test_query() above may have loaded the real PSL for its
	 * use_tld_list==TRUE cases.  opendmarc_get_tld() has no notion of the
	 * dmarcwalk.gushi.org delegation, so with a PSL loaded it would
	 * collapse both gushi.org and dmarcwalk.gushi.org to the same
	 * registrable domain "gushi.org" and short-circuit the cases below
	 * that depend on them being treated as different organizations.
	 * Force a clean, no-PSL starting state.
	 */
	opendmarc_tld_shutdown();

	successes = failures = 0;
	for (dp = domain_list; dp->domain != NULL; ++dp)
	{
		pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
		pctx->from_domain = (u_char *)strdup(dp->domain);
		status = opendmarc_policy_query_dmarc_xdomain(pctx, (u_char *)dp->uri);

		pctx = opendmarc_policy_connect_shutdown(pctx);
		if (status != dp->status)
		{
			printf("\t%s(%d): %s, %s: %d: FAIL.\n", __FILE__, __LINE__, dp->domain, dp->uri, status);
			++failures;
		}
		else
		{
			++successes;
		}
	}

	printf("Test opendmarc_policy_query_dmarc_xdomain(): %d pass, %d fail\n", successes, failures);
	return failures;
}

int
main(int argc, char **argv)
{
	if (dmarc_dns_test_record() != 0)
		return 1;
	if (dmarc_dns_test_query() != 0)
		return 1;
	if (dmarc_dns_test_xdomain_query() != 0)
		return 1;
	return 0;
}
