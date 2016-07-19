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
	int n;
	int pct;
	OPENDMARC_STATUS_T status;
	char *p;
	char *sp;
	char *adkim;
	char *aspf;
	unsigned char **rua;
	unsigned char **ruf;
	DMARC_POLICY_T *dmarc;
	OPENDMARC_LIB_T lib;

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	if (argc == 1)
	{
		fprintf(stderr, "%s: usage: %s [domain [...]]\n", progname,
		        progname);

		return EX_USAGE;
	}

	memset(&lib, '\0', sizeof lib);
	lib.tld_type = OPENDMARC_TLD_TYPE_NONE;
	lib.nscount = 0;

	status = opendmarc_policy_library_init(&lib);
	if (status != DMARC_PARSE_OKAY)
	{
		fprintf(stderr, "%s: opendmarc_policy_library_init(): %s\n",
		        progname,
		        opendmarc_policy_status_to_str(status));

		return EX_SOFTWARE;
	}

	dmarc = opendmarc_policy_connect_init(LOCALHOST, FALSE);
	if (dmarc == NULL)
	{
		fprintf(stderr, "%s: opendmarc_policy_connect_init() failed\n",
		        progname);

		return EX_SOFTWARE;
	}

	for (c = 1; c < argc; c++)
	{
		(void) opendmarc_policy_connect_rset(dmarc);

		status = opendmarc_policy_store_from_domain(dmarc, argv[c]);
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

		if (c != 1)
			fprintf(stdout, "\n");

		(void) opendmarc_policy_fetch_pct(dmarc, &pct);

		(void) opendmarc_policy_fetch_adkim(dmarc, &n);
		switch (n)
		{
		  case DMARC_RECORD_A_UNSPECIFIED:
			adkim = "unspecified";
			break;

		  case DMARC_RECORD_A_STRICT:
			adkim = "strict";
			break;

		  case DMARC_RECORD_A_RELAXED:
			adkim = "relaxed";
			break;

		  default:
			adkim = "unknown";
			break;
		}

		(void) opendmarc_policy_fetch_aspf(dmarc, &n);
		switch (n)
		{
		  case DMARC_RECORD_A_UNSPECIFIED:
			aspf = "unspecified";
			break;

		  case DMARC_RECORD_A_STRICT:
			aspf = "strict";
			break;

		  case DMARC_RECORD_A_RELAXED:
			aspf = "relaxed";
			break;

		  default:
			aspf = "unknown";
			break;
		}

		(void) opendmarc_policy_fetch_p(dmarc, &n);
		switch (n)
		{
		  case DMARC_RECORD_P_UNSPECIFIED:
			p = "unspecified";
			break;

		  case DMARC_RECORD_P_NONE:
			p = "none";
			break;

		  case DMARC_RECORD_P_QUARANTINE:
			p = "quarantine";
			break;

		  case DMARC_RECORD_P_REJECT:
			p = "reject";
			break;

		  default:
			p = "unknown";
			break;
		}

		(void) opendmarc_policy_fetch_sp(dmarc, &n);
		switch (n)
		{
		  case DMARC_RECORD_P_UNSPECIFIED:
			sp = "unspecified";
			break;

		  case DMARC_RECORD_P_NONE:
			sp = "none";
			break;

		  case DMARC_RECORD_P_QUARANTINE:
			sp = "quarantine";
			break;

		  case DMARC_RECORD_P_REJECT:
			sp = "reject";
			break;

		  default:
			sp = "unknown";
			break;
		}

		rua = opendmarc_policy_fetch_rua(dmarc, NULL, 0, 1);
		ruf = opendmarc_policy_fetch_ruf(dmarc, NULL, 0, 1);

		fprintf(stdout, "DMARC record for %s:\n", argv[1]);
		fprintf(stdout, "\tSample percentage: %d\n", pct);
		fprintf(stdout, "\tDKIM alignment: %s\n", adkim);
		fprintf(stdout, "\tSPF alignment: %s\n", aspf);
		fprintf(stdout, "\tDomain policy: %s\n", p);
		fprintf(stdout, "\tSubdomain policy: %s\n", sp);
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
