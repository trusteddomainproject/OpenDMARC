/*
** test_dmarc_walk.c -- live DNS test for DMARCbis walk-mode selection
**
** Exercises opendmarc_policy_query_dmarc() under the OPENDMARC_WALK_MODE_*
** strategies against the real dmarcwalk.gushi.org records.  See
** testfiles/test-dns.zone.inc (the "dmarcwalk" section) for those records
** and the reasoning behind each scenario below -- this file follows that
** documentation case by case.  That file is a portable, domain-agnostic
** template; the live dmarcwalk.gushi.org zone is simply its "dmarcwalk"
** section deployed under gushi.org.
**
** This is a live-network test: it requires --enable-live-tests and a
** resolver that can actually reach gushi.org's public DNS, which is why
** it is gated the same way test_spf.c is.
**
** The PSL-loaded divergence case documented in the zone file (PSL/AUTO
** falling through to gushi.org's real, independently managed apex record)
** is intentionally not asserted here: its correct answer depends on
** production DNS data outside this fixture's control.  Only the PSL
** no-record case (no PSL loaded at all) is checked, since that outcome
** is deterministic.
*/

#include "../opendmarc_internal.h"
#include "../dmarc.h"

#define ZONE "dmarcwalk.gushi.org"

#define CHECK(cond, msg) \
	do { \
		count++; \
		if (cond) { \
			pass++; \
		} else { \
			printf("\t%s(%d): %s: FAIL\n", __FILE__, __LINE__, msg); \
			fails++; \
		} \
	} while (0)

static OPENDMARC_STATUS_T
set_mode(int mode)
{
	OPENDMARC_LIB_T lib;

	memset(&lib, '\0', sizeof lib);
	lib.tld_type = OPENDMARC_TLD_TYPE_NONE;
	lib.walk_mode = mode;
	return opendmarc_policy_library_init(&lib);
}

static OPENDMARC_STATUS_T
set_mode_with_fallback(int mode, int fallback_mode)
{
	OPENDMARC_LIB_T lib;

	memset(&lib, '\0', sizeof lib);
	lib.tld_type = OPENDMARC_TLD_TYPE_NONE;
	lib.walk_mode = mode;
	lib.walk_mode_fallback = fallback_mode;
	return opendmarc_policy_library_init(&lib);
}

int
main(int argc, char **argv)
{
	int pass = 0, fails = 0, count = 0;
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;
	u_char utilized[256];
	int fallback;
	int discovery_method;

	/*
	 * === Test 0: direct hit ===
	 * direct.dmarcwalk.gushi.org has its own record; no walk should occur
	 * in any mode, so the mode chosen here (AUTO) is arbitrary.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_AUTO);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"direct." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "direct hit: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "direct." ZONE) == 0,
		    "direct hit: utilized domain should be the queried name itself");

		(void) opendmarc_policy_fetch_org_domain_from_fallback(pctx, &fallback);
		CHECK(fallback == 0, "direct hit: no fallback should have occurred");

		(void) opendmarc_policy_fetch_discovery_method(pctx, &discovery_method);
		CHECK(discovery_method == OPENDMARC_DISCOVERY_UNSPECIFIED,
		    "direct hit: discovery_method should be unspecified, no walk occurred");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Tests 1-2: psd=n stops the walk at the level it is found ===
	 * sub.psdn.dmarcwalk.gushi.org has no record of its own.
	 * psdn.dmarcwalk.gushi.org has psd=n.  rfc9989 stops there on its
	 * first query (S4.10 step 2); rfc7489's one-level walk lands on the
	 * same name with no psd= concept at all.  Same answer, different
	 * reasoning.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_RFC9989);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.psdn." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc9989 psd=n: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "psdn." ZONE) == 0,
		    "rfc9989 psd=n: org domain should be psdn.dmarcwalk.gushi.org");

		(void) opendmarc_policy_fetch_discovery_method(pctx, &discovery_method);
		CHECK(discovery_method == OPENDMARC_DISCOVERY_TREEWALK,
		    "rfc9989 psd=n: discovery_method should be treewalk");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	(void) set_mode(OPENDMARC_WALK_MODE_RFC7489);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.psdn." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc7489 psd=n name: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "psdn." ZONE) == 0,
		    "rfc7489 psd=n name: org domain should agree with rfc9989");

		(void) opendmarc_policy_fetch_org_domain_from_fallback(pctx, &fallback);
		CHECK(fallback == 1, "rfc7489 psd=n name: fallback flag should be set");

		(void) opendmarc_policy_fetch_discovery_method(pctx, &discovery_method);
		CHECK(discovery_method == OPENDMARC_DISCOVERY_PSL,
		    "rfc7489 psd=n name: discovery_method should be psl (RFC 9990's name for the RFC 7489 method)");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Tests 3-4: no psd= tag, reached by two different mechanisms ===
	 * sub.nopsd.dmarcwalk.gushi.org has no record.  nopsd.dmarcwalk.gushi.org
	 * has p=quarantine with no psd= tag.  rfc7489's one-level walk lands
	 * there directly.  rfc9989 doesn't stop on a record with no psd=, so it
	 * keeps walking, hits the apex's psd=y, and backs off one label -- which
	 * resolves back to the same name.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_RFC9989);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.nopsd." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc9989 no psd=: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "nopsd." ZONE) == 0,
		    "rfc9989 no psd=: org domain should be nopsd.dmarcwalk.gushi.org");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	(void) set_mode(OPENDMARC_WALK_MODE_RFC7489);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.nopsd." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc7489 no psd= name: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "nopsd." ZONE) == 0,
		    "rfc7489 no psd= name: org domain should agree with rfc9989");

		(void) opendmarc_policy_fetch_org_domain_from_fallback(pctx, &fallback);
		CHECK(fallback == 1, "rfc7489 no psd= name: fallback flag should be set");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Tests 5-6: psd=y -- the genuine, intentional divergence ===
	 * leaf.mid.psdy.dmarcwalk.gushi.org has no record, nor does
	 * mid.psdy.dmarcwalk.gushi.org.  psdy.dmarcwalk.gushi.org has psd=y.
	 * rfc9989 backs off one label below the psd=y record (S4.10.2 step 2),
	 * landing on mid.psdy.dmarcwalk.gushi.org.  rfc7489 has no psd= concept
	 * and just stops on the first record it finds: psdy.dmarcwalk.gushi.org
	 * itself.  These must NOT match -- that is the point of this fixture.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_RFC9989);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"leaf.mid.psdy." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc9989 psd=y: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "mid.psdy." ZONE) == 0,
		    "rfc9989 psd=y: org domain should back off to mid.psdy.dmarcwalk.gushi.org");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	(void) set_mode(OPENDMARC_WALK_MODE_RFC7489);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"leaf.mid.psdy." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc7489 psd=y name: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "psdy." ZONE) == 0,
		    "rfc7489 psd=y name: org domain should be psdy.dmarcwalk.gushi.org, diverging from rfc9989");

		(void) opendmarc_policy_fetch_org_domain_from_fallback(pctx, &fallback);
		CHECK(fallback == 1, "rfc7489 psd=y name: fallback flag should be set");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Tests 7-8: >8 labels -- rfc9989's S4.10 step 4 shortening ===
	 * d6.d5.d4.d3.d2.d1.eightlabel.dmarcwalk.gushi.org is 10 labels deep.
	 * d3.d2.d1.eightlabel.dmarcwalk.gushi.org has psd=n and sits exactly 7
	 * labels from the root.  Both modes land on the same org domain;
	 * rfc9989 gets there in its first query, rfc7489 takes three.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_RFC9989);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx,
	    (u_char *)"d6.d5.d4.d3.d2.d1.eightlabel." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc9989 >8 labels: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "d3.d2.d1.eightlabel." ZONE) == 0,
		    "rfc9989 >8 labels: org domain should be d3.d2.d1.eightlabel.dmarcwalk.gushi.org");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	(void) set_mode(OPENDMARC_WALK_MODE_RFC7489);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx,
	    (u_char *)"d6.d5.d4.d3.d2.d1.eightlabel." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc7489 >8 labels: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "d3.d2.d1.eightlabel." ZONE) == 0,
		    "rfc7489 >8 labels: org domain should agree with rfc9989 despite more queries");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Tests 9-10: multiple records at one name, then divergence ===
	 * multirecord.dmarcwalk.gushi.org carries two v=DMARC1 TXT records, so
	 * the direct query there must be discarded (RFC 7489 S6.6.3 step 5 /
	 * RFC 9989 S4.10 steps 2 and 6).  The walk then continues from there:
	 * rfc9989 reaches the apex's psd=y and backs off one label, landing
	 * back on multirecord.dmarcwalk.gushi.org -- the very name whose direct
	 * record was just discarded, which is correct: the discard applies to
	 * that one query, not to the name's eligibility as an org domain found
	 * via a different path.  rfc7489 has no psd= concept and takes the
	 * apex's record as-is, so its org domain is dmarcwalk.gushi.org itself
	 * -- a genuine divergence from rfc9989.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_RFC9989);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"multirecord." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc9989 multirecord: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "multirecord." ZONE) == 0,
		    "rfc9989 multirecord: org domain should be multirecord.dmarcwalk.gushi.org");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	(void) set_mode(OPENDMARC_WALK_MODE_RFC7489);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"multirecord." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "rfc7489 multirecord: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, ZONE) == 0,
		    "rfc7489 multirecord: org domain should be dmarcwalk.gushi.org, diverging from rfc9989");

		(void) opendmarc_policy_fetch_org_domain_from_fallback(pctx, &fallback);
		CHECK(fallback == 1, "rfc7489 multirecord: fallback flag should be set");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Tests 11-12: PSL mode and AUTO with no PSL loaded ===
	 * Without a PSL file, opendmarc_get_tld() returns the queried domain
	 * unchanged, so PSL mode can never identify an org domain and must
	 * fail outright.  AUTO tries PSL first, then falls back to the same
	 * rfc7489 walk used above.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_PSL);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.nopsd." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_DNS_ERROR_NO_RECORD,
	    "psl with no PSL loaded: should return DMARC_DNS_ERROR_NO_RECORD");

	pctx = opendmarc_policy_connect_shutdown(pctx);

	(void) set_mode(OPENDMARC_WALK_MODE_AUTO);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.nopsd." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "auto with no PSL loaded: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "nopsd." ZONE) == 0,
		    "auto with no PSL loaded: org domain should match the rfc7489 walk");

		(void) opendmarc_policy_fetch_org_domain_from_fallback(pctx, &fallback);
		CHECK(fallback == 1, "auto with no PSL loaded: fallback flag should be set");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Test 13: walk_mode_fallback ===
	 * Same query as test 11 (PSL, no PSL loaded, so PSL alone fails), but
	 * with RFC9989 configured as walk_mode_fallback.  Unlike AUTO, whose
	 * PSL-then-RFC7489 combinator is fixed, this lets PSL fail over to
	 * whichever strategy is configured -- here, RFC9989 -- and should land
	 * on the same nopsd.dmarcwalk.gushi.org answer as test 3.
	 */
	(void) set_mode_with_fallback(OPENDMARC_WALK_MODE_PSL, OPENDMARC_WALK_MODE_RFC9989);
	pctx = opendmarc_policy_connect_init((u_char *)"0.0.0.0", FALSE);
	if (pctx == NULL) { fprintf(stderr, "connect_init failed\n"); return 1; }

	(void) opendmarc_policy_store_from_domain(pctx, (u_char *)"sub.nopsd." ZONE);
	status = opendmarc_policy_query_dmarc(pctx, NULL);

	CHECK(status == DMARC_PARSE_OKAY,
	    "psl falling back to rfc9989: query should return DMARC_PARSE_OKAY");
	if (status == DMARC_PARSE_OKAY)
	{
		(void) memset(utilized, '\0', sizeof utilized);
		(void) opendmarc_policy_fetch_utilized_domain(pctx, utilized, sizeof utilized);
		CHECK(strcasecmp((char *)utilized, "nopsd." ZONE) == 0,
		    "psl falling back to rfc9989: org domain should be nopsd.dmarcwalk.gushi.org");

		(void) opendmarc_policy_fetch_discovery_method(pctx, &discovery_method);
		CHECK(discovery_method == OPENDMARC_DISCOVERY_TREEWALK,
		    "psl falling back to rfc9989: discovery_method should reflect rfc9989, the strategy that actually resolved it");
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);

	/*
	 * === Tests 14-16: secondary alignment walk (S 4.10.2) ===
	 * opendmarc_policy_check_alignment() takes no pctx, so these call it
	 * directly rather than through the connect/store/query path above.
	 *
	 * "othersub.nopsd." ZONE and "sub.nopsd." ZONE are siblings: neither is
	 * a literal suffix of the other, so the cheap substring checks that run
	 * before any organizational-domain reduction cannot match them.  The
	 * only way they align is if "sub.nopsd." ZONE gets reduced to
	 * "nopsd." ZONE -- which is also "othersub." ZONE's organizational
	 * domain -- via the configured walk strategy.
	 */
	(void) set_mode(OPENDMARC_WALK_MODE_RFC9989);
	CHECK(opendmarc_policy_check_alignment((u_char *)"othersub.nopsd." ZONE,
	                                        (u_char *)"sub.nopsd." ZONE,
	                                        DMARC_RECORD_A_RELAXED) == 0,
	    "rfc9989 secondary alignment walk: siblings under nopsd." ZONE " should align");

	(void) set_mode(OPENDMARC_WALK_MODE_PSL);
	CHECK(opendmarc_policy_check_alignment((u_char *)"othersub.nopsd." ZONE,
	                                        (u_char *)"sub.nopsd." ZONE,
	                                        DMARC_RECORD_A_RELAXED) != 0,
	    "psl with no PSL loaded: siblings should not align, no boundary available");

	(void) set_mode_with_fallback(OPENDMARC_WALK_MODE_PSL, OPENDMARC_WALK_MODE_RFC9989);
	CHECK(opendmarc_policy_check_alignment((u_char *)"othersub.nopsd." ZONE,
	                                        (u_char *)"sub.nopsd." ZONE,
	                                        DMARC_RECORD_A_RELAXED) == 0,
	    "psl falling back to rfc9989: secondary alignment walk should align via the fallback");

	printf("DMARC walk-mode live test (%s): pass=%d, fail=%d\n", ZONE, pass, fails);
	return fails;
}
