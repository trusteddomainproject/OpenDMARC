/*
**  Copyright (c) 2018, The Trusted Domain Project.
**  	All rights reserved.
**
**  Implements functionality required to extract ARC seal details for inclusion
**  in DMARC reporting.
*/

#ifndef _OPENDMARC_ARCSEAL_H_
#define _OPENDMARC_ARCSEAL_H_

/* system includes */
#include <sys/types.h>

/* opendmarc includes */
#include "parse.h"

/* boolean TRUE and FALSE */
#ifndef FALSE
# define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* !TRUE */

/*
** limits
*/

/* buffer to cache a single header */
#define OPENDMARC_ARCSEAL_MAXHEADER_LEN       4096
/* max header tag value length (short) */
#define OPENDMARC_ARCSEAL_MAX_SHORT_VALUE_LEN 256
/* max header tag value length (long) */
#define OPENDMARC_ARCSEAL_MAX_LONG_VALUE_LEN  512

/* names and field labels */
#define OPENDMARC_ARCSEAL_HDRNAME	"ARC-Seal"
#define OPENDMARC_ARCSEAL_HDRNAME_LEN	sizeof(OPENDMARC_ARCSEAL_HDRNAME) - 1

/* AS_TAG_T -- type for specifying arc seal tag names */
typedef int as_tag_t;

#define AS_TAG_UNKNOWN            (-1)
#define AS_TAG_ALGORITHM          0
#define AS_TAG_CHAIN_VALIDATION   1
#define AS_TAG_INSTANCE           2
#define AS_TAG_SIGNATURE_DOMAIN   3
#define AS_TAG_SIGNATURE_SELECTOR 4
#define AS_TAG_SIGNATURE_TIME     5
#define AS_TAG_SIGNATURE_VALUE    6

/* ARCSEAL structure -- the single header parsed */
struct arcseal
{
	int instance;
	char algorithm[OPENDMARC_ARCSEAL_MAX_SHORT_VALUE_LEN + 1];
	char chain_validation[OPENDMARC_ARCSEAL_MAX_SHORT_VALUE_LEN + 1];
	char signature_domain[OPENDMARC_ARCSEAL_MAX_SHORT_VALUE_LEN + 1];
	char signature_selector[OPENDMARC_ARCSEAL_MAX_SHORT_VALUE_LEN + 1];
	char signature_time[OPENDMARC_ARCSEAL_MAX_SHORT_VALUE_LEN + 1];
	char signature_value[OPENDMARC_ARCSEAL_MAX_LONG_VALUE_LEN + 1];
};

/* ARCSEAL_HEADER -- a node for a linked list of arcseal structs */
struct arcseal_header
{
	struct arcseal arcseal;
	struct arcseal_header * arcseal_next;
	struct arcseal_header * arcseal_prev;
};

/*
**  OPENDMARC_ARC_SEAL_PARSE -- parse an ARC-Seal: header, return a structure
**                              containing a parsed result
**
**  Parameters:
**  	hdr -- NULL-terminated contents of an ARC-Seal: header field
**  	as  -- a pointer to a (struct arcseal) loaded by values after parsing
**
**  Returns:
**  	0 on success, -1 on failure
**/

extern int opendmarc_arcseal_parse __P((char *hdr, struct arcseal *as));

#endif /* _OPENDMARC_ARCSEAL_H_ */
