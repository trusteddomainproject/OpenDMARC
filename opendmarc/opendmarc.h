/*
**  Copyright (c) 2012, 2013, 2015, The Trusted Domain Project.
**  	All rights reserved.
*/

#ifndef _OPENDMARC_H_
#define _OPENDMARC_H_

#define	DMARCF_PRODUCT		"OpenDMARC Filter"
#define	DMARCF_PRODUCTNS	"OpenDMARC-Filter"

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libmilter */
#include <libmilter/mfapi.h>

#include "dmarc.h"

/* make sure we have TRUE and FALSE */
#ifndef FALSE
# define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* !TRUE */

/* defaults, limits, etc. */
#define	BUFRSZ		2048
#define	DEFCONFFILE	CONFIG_BASE "/opendmarc.conf"
#define	DEFREPORTCMD	"/usr/sbin/sendmail -t -odq"
#define	JOBIDUNKNOWN	"(unknown-jobid)"
#define	MAXARGV		65536
#define	MAXHEADER	1024
#define	TEMPFILE	"/var/tmp/dmarcXXXXXX"

#define AUTHRESULTSHDR	"Authentication-Results"
#define	SWHEADERNAME	"DMARC-Filter"

#define	DMARC_TEMPFAIL_SMTP	"451"
#define	DMARC_TEMPFAIL_ESC	"4.7.1"
#define	DMARC_REJECT_SMTP	"550"
#define	DMARC_REJECT_ESC	"5.7.1"

#define	DMARC_RESULT_REJECT	0
#define	DMARC_RESULT_DISCARD	1
#define	DMARC_RESULT_ACCEPT	2
#define	DMARC_RESULT_TEMPFAIL	3
#define	DMARC_RESULT_QUARANTINE	4

/* prototypes, etc., exported for test.c */
extern char *progname;

extern sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
#ifdef WITH_SPF
extern sfsistat mlfi_helo __P((SMFICTX *, char *));
#endif /* WITH_SPF */
extern sfsistat mlfi_envfrom __P((SMFICTX *, char **));
extern sfsistat mlfi_header __P((SMFICTX *, char *, char *));
extern sfsistat mlfi_eoh __P((SMFICTX *));
extern sfsistat mlfi_eom __P((SMFICTX *));
extern sfsistat mlfi_abort __P((SMFICTX *));
extern sfsistat mlfi_close __P((SMFICTX *));

#endif /* _OPENDMARC_H_ */
