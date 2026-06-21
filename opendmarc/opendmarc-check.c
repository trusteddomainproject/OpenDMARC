/*
**  Copyright (c) 2012, 2014, 2016, The Trusted Domain Project.
**  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sysexits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendmarc_strl if needed */
#ifdef USE_DMARCSTRL_H
# include <opendmarc_strl.h>
#endif /* USE_DMARCSTRL_H */

/* libopendmarc */
#include <dmarc.h>

#define LOCALHOST	"127.0.0.1"

#ifndef TRUE
# define TRUE 1
#endif /* ! TRUE */
#ifndef FALSE
# define FALSE 0
#endif /* ! FALSE */

/* globals */
char *progname;

/*
**  USAGE -- print a usage message
*/

static void
usage(void)
{
	fprintf(stderr,
	        "%s: usage: %s [-p pslfile] [-m mode | -a] domain [domain ...]\n"
	        "\t-p pslfile  path to a Public Suffix List file\n"
	        "\t-m mode     walk mode: auto (default), psl, rfc7489, rfc9989\n"
	        "\t-a          query all four walk modes per domain and compare\n",
	        progname, progname);
}

/*
**  PARSE_WALK_MODE -- translate a mode name to an OPENDMARC_WALK_MODE_* value
**
**  Returns TRUE on success, FALSE if the name is not recognized.
*/

static int
parse_walk_mode(const char *name, int *modep)
{
	if (strcasecmp(name, "auto") == 0)
		*modep = OPENDMARC_WALK_MODE_AUTO;
	else if (strcasecmp(name, "psl") == 0)
		*modep = OPENDMARC_WALK_MODE_PSL;
	else if (strcasecmp(name, "rfc7489") == 0)
		*modep = OPENDMARC_WALK_MODE_RFC7489;
	else if (strcasecmp(name, "rfc9989") == 0)
		*modep = OPENDMARC_WALK_MODE_RFC9989;
	else
		return FALSE;

	return TRUE;
}

/*
**  WALK_MODE_TO_STR -- name of an OPENDMARC_WALK_MODE_* value
*/

static const char *
walk_mode_to_str(int mode)
{
	switch (mode)
	{
	  case OPENDMARC_WALK_MODE_PSL:
		return "psl";

	  case OPENDMARC_WALK_MODE_RFC7489:
		return "rfc7489";

	  case OPENDMARC_WALK_MODE_RFC9989:
		return "rfc9989";

	  case OPENDMARC_WALK_MODE_AUTO:
	  default:
		return "auto";
	}
}

/*
**  POLICY_TO_STR -- human-readable name of a DMARC_RECORD_P_* value
*/

static const char *
policy_to_str(int p)
{
	switch (p)
	{
	  case DMARC_RECORD_P_NONE:
		return "none";

	  case DMARC_RECORD_P_QUARANTINE:
		return "quarantine";

	  case DMARC_RECORD_P_REJECT:
		return "reject";

	  case DMARC_RECORD_P_UNSPECIFIED:
		return "unspecified";

	  default:
		return "unknown";
	}
}

/*
**  ALIGNMENT_TO_STR -- human-readable name of a DMARC_RECORD_A_* value
*/

static const char *
alignment_to_str(int a)
{
	switch (a)
	{
	  case DMARC_RECORD_A_STRICT:
		return "strict";

	  case DMARC_RECORD_A_RELAXED:
		return "relaxed";

	  case DMARC_RECORD_A_UNSPECIFIED:
		return "unspecified";

	  default:
		return "unknown";
	}
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	int c;
	int i;
	int n;
	int ch;
	int pct;
	int compare_all = FALSE;
	int mode_given = FALSE;
	int walk_mode = OPENDMARC_WALK_MODE_AUTO;
	char *pslfile = NULL;
	OPENDMARC_STATUS_T status;
	char *p;
	const char *adkim;
	const char *aspf;
	const char *pstr;
	const char *spstr;
	unsigned char **rua;
	unsigned char **ruf;
	DMARC_POLICY_T *dmarc;
	OPENDMARC_LIB_T lib;
	static const int all_modes[] = { OPENDMARC_WALK_MODE_AUTO,
		                          OPENDMARC_WALK_MODE_PSL,
		                          OPENDMARC_WALK_MODE_RFC7489,
		                          OPENDMARC_WALK_MODE_RFC9989 };

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((ch = getopt(argc, argv, "am:p:h")) != -1)
	{
		switch (ch)
		{
		  case 'a':
			compare_all = TRUE;
			break;

		  case 'm':
			if (!parse_walk_mode(optarg, &walk_mode))
			{
				fprintf(stderr, "%s: unknown walk mode '%s'\n",
				        progname, optarg);
				usage();

				return EX_USAGE;
			}
			mode_given = TRUE;
			break;

		  case 'p':
			pslfile = optarg;
			break;

		  case 'h':
		  default:
			usage();

			return EX_USAGE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
	{
		usage();

		return EX_USAGE;
	}

	if (compare_all && mode_given)
	{
		fprintf(stderr, "%s: -m and -a are mutually exclusive\n", progname);
		usage();

		return EX_USAGE;
	}

	memset(&lib, '\0', sizeof lib);
	lib.tld_type = OPENDMARC_TLD_TYPE_NONE;
	lib.nscount = 0;
	if (pslfile != NULL)
	{
		lib.tld_type = OPENDMARC_TLD_TYPE_MOZILLA;
		(void) strlcpy((char *)lib.tld_source_file, pslfile,
		               sizeof lib.tld_source_file);
	}
	lib.walk_mode = walk_mode;

	status = opendmarc_policy_library_init(&lib);
	if (status != DMARC_PARSE_OKAY)
	{
		fprintf(stderr, "%s: opendmarc_policy_library_init(): %s\n",
		        progname,
		        opendmarc_policy_status_to_str(status));

		return EX_SOFTWARE;
	}

	dmarc = opendmarc_policy_connect_init((u_char *)LOCALHOST, FALSE);
	if (dmarc == NULL)
	{
		fprintf(stderr, "%s: opendmarc_policy_connect_init() failed\n",
		        progname);

		return EX_SOFTWARE;
	}

	for (c = 0; c < argc; c++)
	{
		if (c != 0)
			fprintf(stdout, "\n");

		if (compare_all)
		{
			fprintf(stdout, "%s\n", argv[c]);

			for (i = 0; i < (int) (sizeof all_modes / sizeof all_modes[0]); i++)
			{
				u_char orgbuf[256];
				int fallback = 0;
				int p_n = DMARC_RECORD_P_UNSPECIFIED;
				int sp_n = DMARC_RECORD_P_UNSPECIFIED;

				/*
				 * Re-init with the next mode; this exercises the same
				 * connect/store/query path the milter uses, just with
				 * walk_mode swapped between runs.
				 */
				lib.walk_mode = all_modes[i];
				(void) opendmarc_policy_library_init(&lib);
				(void) opendmarc_policy_connect_rset(dmarc);

				status = opendmarc_policy_store_from_domain(dmarc,
				                                             (u_char *) argv[c]);
				if (status == DMARC_PARSE_OKAY)
					status = opendmarc_policy_query_dmarc(dmarc, NULL);

				memset(orgbuf, '\0', sizeof orgbuf);
				if (status == DMARC_PARSE_OKAY)
				{
					(void) opendmarc_policy_fetch_utilized_domain(dmarc,
					                                               orgbuf,
					                                               sizeof orgbuf);
					(void) opendmarc_policy_fetch_org_domain_from_fallback(dmarc,
					                                                        &fallback);
					(void) opendmarc_policy_fetch_p(dmarc, &p_n);
					(void) opendmarc_policy_fetch_sp(dmarc, &sp_n);
				}

				fprintf(stdout,
				        "  %-8s %-26s org=%-28s p=%-12s sp=%-12s fallback=%s\n",
				        walk_mode_to_str(all_modes[i]),
				        opendmarc_policy_status_to_str(status),
				        status == DMARC_PARSE_OKAY ? (char *) orgbuf : "-",
				        status == DMARC_PARSE_OKAY ? policy_to_str(p_n) : "-",
				        status == DMARC_PARSE_OKAY ? policy_to_str(sp_n) : "-",
				        fallback ? "yes" : "no");
			}

			continue;
		}

		(void) opendmarc_policy_connect_rset(dmarc);

		status = opendmarc_policy_store_from_domain(dmarc, (u_char *) argv[c]);
		if (status != DMARC_PARSE_OKAY)
		{
			fprintf(stderr,
			        "%s: opendmarc_policy_store_from_domain(%s): %s\n",
			        progname, argv[c],
			        opendmarc_policy_status_to_str(status));

			return EX_SOFTWARE;
		}

		status = opendmarc_policy_query_dmarc(dmarc, NULL);
		if (status != DMARC_PARSE_OKAY)
		{
			fprintf(stderr,
			        "%s: opendmarc_policy_query_dmarc(%s): %s\n",
			        progname, argv[c],
			        opendmarc_policy_status_to_str(status));

			return EX_SOFTWARE;
		}

		(void) opendmarc_policy_fetch_pct(dmarc, &n);
		pct = n;

		(void) opendmarc_policy_fetch_adkim(dmarc, &n);
		adkim = alignment_to_str(n);

		(void) opendmarc_policy_fetch_aspf(dmarc, &n);
		aspf = alignment_to_str(n);

		(void) opendmarc_policy_fetch_p(dmarc, &n);
		pstr = policy_to_str(n);

		(void) opendmarc_policy_fetch_sp(dmarc, &n);
		spstr = policy_to_str(n);

		rua = opendmarc_policy_fetch_rua(dmarc, NULL, 0, 1);
		ruf = opendmarc_policy_fetch_ruf(dmarc, NULL, 0, 1);

		fprintf(stdout, "DMARC record for %s:\n", argv[c]);
		fprintf(stdout, "\tSample percentage: %d\n", pct);
		fprintf(stdout, "\tDKIM alignment: %s\n", adkim);
		fprintf(stdout, "\tSPF alignment: %s\n", aspf);
		fprintf(stdout, "\tDomain policy: %s\n", pstr);
		fprintf(stdout, "\tSubdomain policy: %s\n", spstr);
		fprintf(stdout, "\tAggregate report URIs:\n");
		for (n = 0; rua != NULL && rua[n] != NULL; n++)
			fprintf(stdout, "\t\t%s\n", rua[n]);
		if (n == 0)
			fprintf(stdout, "\t\t(none)\n");
		fprintf(stdout, "\tFailure report URIs:\n");
		for (n = 0; ruf != NULL && ruf[n] != NULL; n++)
			fprintf(stdout, "\t\t%s\n", ruf[n]);
		if (n == 0)
			fprintf(stdout, "\t\t(none)\n");
	}

	(void) opendmarc_policy_connect_shutdown(dmarc);
	(void) opendmarc_policy_library_shutdown(&lib);

	return EX_OK;
}
