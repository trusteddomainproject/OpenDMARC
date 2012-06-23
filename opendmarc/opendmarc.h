/*
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
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

/* libopendmarc */
/* #include "libopendmarc.h"
/* XXX -- not yet available... -- #include "dmarc.h" */

/* make sure we have TRUE and FALSE */
#ifndef FALSE
# define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* !TRUE */

/* defaults, limits, etc. */
#define	BUFRSZ		1024
#define	DEFCONFFILE	CONFIG_BASE "/opendmarc.conf"
#define	JOBIDUNKNOWN	"(unknown-jobid)"
#define	MAXARGV		65536
#define	MAXHEADER	1024
#define	TEMPFILE	"/var/tmp/dmarcXXXXXX"

#define AUTHRESULTSHDR	"Authentication-Results"
#define	SWHEADERNAME	"DMARC-Filter"

#endif /* _OPENDMARC_H_ */
