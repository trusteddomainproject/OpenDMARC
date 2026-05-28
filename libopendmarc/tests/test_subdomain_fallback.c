/*
** test_subdomain_fallback.c -- regression test for issue #54
**
** When a subdomain has no _dmarc record, opendmarc_policy_query_dmarc()
** must fall back to the organizational/parent domain's DMARC record
** per RFC 7489 §6.6.3.
**
** Before the fix, when no PublicSuffixList was configured, opendmarc_get_tld()
** returned the queried domain unchanged.  The fallback then re-queried the
** same _dmarc name, which also had no record, and the function returned
** DMARC_DNS_ERROR_NO_RECORD regardless of whether a parent had a record.
**
** The fix adds a label-walking fallback for the no-PSL case, and keeps the
** existing PSL-based single-lookup path for the case where a PSL is loaded.
**
** Distinct domain names are used for each test to avoid cross-contamination
** of the global fake-DNS table (entries persist for the process lifetime).
*/

#include "../opendmarc_internal.h"
#include "../dmarc.h"

#define TESTFILE "testfiles/effective_tld_names.dat"

#define CHECK(cond, msg)	\
	do {			\
		count++;	\
		if (cond) {	\
			pass++;	\
		} else {	\
			printf("\t%s(%d): %s: FAIL\n", __FILE__, __LINE__, msg); \
			fails++;	\
		}		\
	} while (0)

int
main(int argc, char **argv)
{
	int pass = 0, fails = 0, count = 0;
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;
	int p;
	u_char utilized[256];
	char *srcdir;

	srcdir = getenv("srcdir");
	if (srcdir != NULL)
	{
		if (chdir(srcdir) != 0)
		{
			perror(srcdir);
			return 1;
		}
	}

	/*
	 * Set up the fake DNS table.  Once any entry is added, dmarc_dns_get_record()
	 * consults only this table for all lookups; names absent from the table
	 * return NO_DATA (simulating "no record found").
	 *
	 * Use a distinct domain per test to avoid cross-contamination.
	 */

	/* Test domains and their fake records. */
	opendmarc_dns_fake_record("_dmarc.parent1.example",
	    "v=DMARC1; p=reject; rua=mailto:dmarc@parent1.example");
	/* _dmarc.sub.parent1.example: absent from table → NO_DATA */

	opendmarc_dns_fake_record("_dmarc.own-record.example",
	    "v=DMARC1; p=quarantine");

	opendmarc_dns_fake_record("_dmarc.parent3.example",
	    "v=DMARC1; p=none; sp=reject");
	/* _dmarc.a.b.parent3.example and _dmarc.b.parent3.example: absent → NO_DATA */

	/* _dmarc.sub.nodmarc.example and _dmarc.nodmarc.example: absent → NO_DATA */

	/* PSL test: bcx.com is recognized as registrable by the test TLD file. */
	opendmarc_dns_fake_record("_dmarc.bcx.com",
	    "v=DMARC1; p=reject");
	/* _dmarc.sub.bcx.com: absent → NO_DATA */

	/*
	 * === Test 1 ===
	 * No PSL.  Subdomain has no record; parent has p=reject.
	 *
	 * Before the fix: returned DMARC_DNS_ERROR_NO_RECORD.
	 * After the fix:  label-walking finds _dmarc.parent1.example → DMARC_PARSE_OKAY.
	 */
	pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.parent1.example");
	status = opendmarc_policy_query_dmarc(pctx, (u_char *)"sub.parent1.example");

	CHECK(status == DMARC_PARSE_OKAY,
	    "no-PSL subdomain fallback: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		opendmarc_policy_fetch_p(pctx, &p);
		CHECK(p == DMARC_RECORD_P_REJECT,
		    "no-PSL subdomain fallback: inherited p= should be reject");

		(void) memset(utilized, '\0', sizeof utilized);
		opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "parent1.example") == 0,
		    "no-PSL subdomain fallback: utilized domain should be parent1.example");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Test 2 ===
	 * Domain with its own DMARC record — no fallback should occur.
	 */
	pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"own-record.example");
	status = opendmarc_policy_query_dmarc(pctx, (u_char *)"own-record.example");

	CHECK(status == DMARC_PARSE_OKAY,
	    "domain with own record: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		opendmarc_policy_fetch_p(pctx, &p);
		CHECK(p == DMARC_RECORD_P_QUARANTINE,
		    "domain with own record: p= should be quarantine");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Test 3 ===
	 * No PSL.  Deeply nested subdomain: a.b.parent3.example.
	 * Neither _dmarc.b.parent3.example nor _dmarc.a.b.parent3.example exist.
	 * Label walk should reach _dmarc.parent3.example (p=none, sp=reject).
	 */
	pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"a.b.parent3.example");
	status = opendmarc_policy_query_dmarc(pctx, (u_char *)"a.b.parent3.example");

	CHECK(status == DMARC_PARSE_OKAY,
	    "no-PSL deeply nested subdomain: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		opendmarc_policy_fetch_p(pctx, &p);
		CHECK(p == DMARC_RECORD_P_NONE,
		    "no-PSL deeply nested subdomain: p= from parent should be none");

		(void) memset(utilized, '\0', sizeof utilized);
		opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "parent3.example") == 0,
		    "no-PSL deeply nested subdomain: utilized domain should be parent3.example");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Test 4 ===
	 * No PSL.  No DMARC record at subdomain or any parent.
	 * Should return DMARC_DNS_ERROR_NO_RECORD (graceful failure).
	 */
	pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.nodmarc.example");
	status = opendmarc_policy_query_dmarc(pctx, (u_char *)"sub.nodmarc.example");

	CHECK(status == DMARC_DNS_ERROR_NO_RECORD,
	    "no-PSL no record anywhere: should return DMARC_DNS_ERROR_NO_RECORD");

	pctx = opendmarc_policy_connect_shutdown(pctx);

	printf("Subdomain fallback (no PSL): pass=%d, fail=%d\n", pass, fails);

	/*
	 * === Tests 5-6: repeat key cases with PSL loaded ===
	 *
	 * With a PSL, opendmarc_get_tld() returns the correct organizational
	 * domain (e.g. bcx.com for sub.bcx.com), so the existing PSL-based
	 * code path is used rather than the new label-walking fallback.
	 */
	if (opendmarc_tld_read_file(TESTFILE, "//", "*.", "!") != 0)
	{
		printf("PSL tests: %s: could not read TLD file, skipping.\n", TESTFILE);
	}
	else
	{
		int psl_pass = 0, psl_fails = 0, psl_count = 0;

#undef CHECK
#define CHECK(cond, msg)	\
		do {			\
			psl_count++;	\
			if (cond) {	\
				psl_pass++;	\
			} else {	\
				printf("\t%s(%d): %s: FAIL\n", __FILE__, __LINE__, msg); \
				psl_fails++;	\
			}		\
		} while (0)

		/*
		 * Test 5: PSL loaded; sub.bcx.com has no record, bcx.com has p=reject.
		 * opendmarc_get_tld("sub.bcx.com") → "bcx.com" (different), so the
		 * PSL path queries _dmarc.bcx.com and finds the record.
		 */
		pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
		if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

		(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.bcx.com");
		status = opendmarc_policy_query_dmarc(pctx, (u_char *)"sub.bcx.com");

		CHECK(status == DMARC_PARSE_OKAY,
		    "PSL subdomain fallback: query should return DMARC_PARSE_OKAY");
		if (status == DMARC_PARSE_OKAY)
		{
			opendmarc_policy_fetch_p(pctx, &p);
			CHECK(p == DMARC_RECORD_P_REJECT,
			    "PSL subdomain fallback: inherited p= should be reject");

			(void) memset(utilized, '\0', sizeof utilized);
			opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
			CHECK(strcasecmp((char *)utilized, "bcx.com") == 0,
			    "PSL subdomain fallback: utilized domain should be bcx.com");
		}

		pctx = opendmarc_policy_connect_shutdown(pctx);

		/*
		 * Test 6: PSL loaded; domain with its own record — no fallback.
		 */
		pctx = opendmarc_policy_connect_init((u_char *)"1.2.3.4", 0);
		if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

		(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"own-record.example");
		status = opendmarc_policy_query_dmarc(pctx, (u_char *)"own-record.example");

		CHECK(status == DMARC_PARSE_OKAY,
		    "PSL domain with own record: query should return DMARC_PARSE_OKAY");
		if (status == DMARC_PARSE_OKAY)
		{
			opendmarc_policy_fetch_p(pctx, &p);
			CHECK(p == DMARC_RECORD_P_QUARANTINE,
			    "PSL domain with own record: p= should be quarantine");
		}

		pctx = opendmarc_policy_connect_shutdown(pctx);

		printf("Subdomain fallback (with PSL): pass=%d, fail=%d\n",
		    psl_pass, psl_fails);

		pass  += psl_pass;
		fails += psl_fails;
	}

	printf("Subdomain fallback overall: pass=%d, fail=%d\n", pass, fails);
	return fails;
}
