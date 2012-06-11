/*
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif /* HAVE_PATHS_H */
#include <sysexits.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

/* opendmarc */
#include "opendmarc.h"
#include "config.h"
#include "opendmarc-ar.h"
#include "opendmarc-config.h"

/* macros */
#define	CMDLINEOPTS	"c:V"

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL	"/dev/null"
#endif /* ! _PATH_DEVNULL */

/* globals */
char *progname;

/*
**  USAGE -- print a usage message and exit
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s [-c conffile] [-V]\n",
	        progname, progname);
	return EX_USAGE;
}

/* XXX -- signal handler functions */
/* XXX -- config reload and apply function */
/* XXX -- milter callbacks */
/* XXX -- milter registration object */

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
	int mvmajor;
	int mvminor;
	int mvrelease;
	int line;
	char *p;
	char *conffile = NULL;
	char *version = NULL;
	struct config *cfg = NULL;
	char path[MAXPATHLEN + 1];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'c':
			conffile = optarg;
			break;

		  case 'V':
			printf("%s: %s v%s\n", progname, DMARCF_PRODUCT,
			       VERSION);
			printf("\tSMFI_VERSION 0x%x\n", SMFI_VERSION);
#ifdef HAVE_SMFI_VERSION
			(void) smfi_version(&mvmajor, &mvminor, &mvrelease);
			printf("\tlibmilter version %d.%d.%d\n",
			       mvmajor, mvminor, mvrelease);
#endif /* HAVE_SMFI_VERSION */
			return EX_OK;

		  default:
			return usage();
		}
	}

	if (conffile == NULL)
		conffile = _PATH_DEVNULL;

	cfg = config_load(conffile, dmarcf_config, &line, path, sizeof path);
	if (cfg == NULL)
	{
		fprintf(stderr, "%s: %s: configuration error at line %u: %s\n",
		        progname, path, line, config_error());
		return EX_CONFIG;
	}

	/* XXX -- create config object */
	/* XXX -- fork if requested */
	/* XXX -- set up signal handlers */
	/* XXX -- change user */
	/* XXX -- open database */
	/* XXX -- register milter stuff */
	/* XXX -- enter milter mode */
	/* XXX -- close database */

	return EX_OK;
}
