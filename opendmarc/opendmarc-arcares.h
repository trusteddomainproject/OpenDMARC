/*
**  Copyright (c) 2018, The Trusted Domain Project.
**  	All rights reserved.
**
**  Implements functionality required to extract ARC authentication results
**  details for inclusion in DMARC reporting.
*/

#ifndef _OPENDMARC_ARCARES_H_
#define _OPENDMARC_ARCARES_H_

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
#define OPENDMARC_ARCARES_MAXHEADER_LEN       4096
/* max header tag value length (short) */
#define OPENDMARC_ARCARES_MAX_SHORT_VALUE_LEN 256
/* max header tag value length (long) */
#define OPENDMARC_ARCARES_MAX_LONG_VALUE_LEN  512

/* names and field labels */
#define OPENDMARC_ARCARES_HDRNAME	"ARC-Authentication-Results"
#define OPENDMARC_ARCARES_HDRNAME_LEN	sizeof(OPENDMARC_ARCARES_HDRNAME) - 1

/* AAR_TAG_T -- type for specifying arc authentication results tag names */
typedef int aar_tag_t;

#define AAR_TAG_UNKNOWN     (-1)
#define AAR_TAG_ARC         0
#define AAR_TAG_AUTHSERV_ID 1
#define AAR_TAG_DKIM        2
#define AAR_TAG_DMARC       3
#define AAR_TAG_INSTANCE    4
#define AAR_TAG_SPF         5

/* AAR_ARC_TAG_T -- type for specifying arc authentication results arc tag names */
typedef int aar_arc_tag_t;

#define AAR_ARC_TAG_UNKNOWN        (-1)
#define AAR_ARC_TAG_ARC            0
#define AAR_ARC_TAG_ARC_CHAIN      1
#define AAR_ARC_TAG_SMTP_CLIENT_IP 2

struct arcares_field
{
	char status[OPENDMARC_ARCARES_MAX_SHORT_VALUE_LEN];
	char string[OPENDMARC_ARCARES_MAX_LONG_VALUE_LEN];
};

/* ARCARES structure -- the single header parsed */
struct arcares
{
	int instance;
	char authserv_id[OPENDMARC_ARCARES_MAX_SHORT_VALUE_LEN + 1];
	char arc[OPENDMARC_ARCARES_MAX_LONG_VALUE_LEN + 1];
	char dkim[OPENDMARC_ARCARES_MAX_LONG_VALUE_LEN + 1];
	char dmarc[OPENDMARC_ARCARES_MAX_LONG_VALUE_LEN + 1];
	char spf[OPENDMARC_ARCARES_MAX_LONG_VALUE_LEN + 1];
};

/* ARCARES_HEADER -- a node for a linked list of arcares structs */
struct arcares_header
{
	struct arcares arcares;
	struct arcares_header * arcares_next;
	struct arcares_header * arcares_prev;
};

struct arcares_arc_field
{
	char arcresult[OPENDMARC_ARCARES_MAX_SHORT_VALUE_LEN + 1];
	char smtpclientip[OPENDMARC_ARCARES_MAX_SHORT_VALUE_LEN + 1];
	char arcchain[OPENDMARC_ARCARES_MAX_LONG_VALUE_LEN + 1];
};

/*
** OPENDMARC_ARCARES_PARSE -- parse an ARC-Authentication-Results: header,
**                             return a structure containing parse result
**
** Parameters:
** 	hdr -- NULL-terminated contents of an ARC-Authentication-Results: header
**             field
** 	aar -- a pointer to a struct (arcaar) loaded by values after parsing
**
**  Returns:
**  	0 on success, -1 on failure
**/

extern int opendmarc_arcares_parse __P((char *hdr, struct arcares *aar));

/*
** OPENDMARC_ARCARES_ARC+PARSE -- parse an ARC-Authentication-Results: header
**                                ARC field, return a structure containing parse
**                                result
**
** Parameters:
** 	hdr_arc -- NULL-terminated contents of an ARC-Authentication-Results:
**                 header ARC field
** 	arc -- a pointer to a struct (arcares_arc_field) loaded by values after
**             parsing
**
**  Returns:
**  	0 on success, -1 on failure
**/

extern int opendmarc_arcares_arc_parse __P((char *hdr_arc,
                                            struct arcares_arc_field *arc));

/*
**  OPENDMARC_ARCARES_LIST_PLUCK -- retrieve a struct (arcares) from a linked
**                                  list corresponding to a specified instance
**
**  Parameters:
**  	instance -- struct with instance value to find
**  	aar_hdr -- address of list head pointer
**  	aar -- a pointer to a struct (arcaar) loaded by values after parsing
**
**  Returns:
**  	0 on success, -1 on failure
*/

extern int opendmarc_arcares_list_pluck(u_int instance,
                                          struct arcares_header *aar_hdr,
                                          struct arcares *aar);

#endif /* _OPENDMARC_ARCARES_H_ */
