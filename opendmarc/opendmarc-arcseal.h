/*
**  Copyright (c) 2018, The Trusted Domain Project.
**  	All rights reserved.
*/

#ifndef _OPENDMARC_ARCSEAL_H_
#define _OPENDMARC_ARCSEAL_H_

/* system includes */
#include <sys/types.h>

/* opendmarc includes */
#include "parse.h"

/* boolean TRUE and FALSE */
#ifndef FALSE
	#define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
	#define TRUE		1
#endif /* !TRUE */

/* limits */
#define ARC_SEAL_MAXHEADER_LEN 4096 		/* buffer to cache a single header */
#define ARC_SEAL_MAX_SHORT_VALUE_LEN 256	/* max header tag value length (short) */
#define ARC_SEAL_MAX_LONG_VALUE_LEN 512		/* max header tag value length (long) */

/* names and field labels */
#define ARC_SEAL_HDRNAME "ARC-Seal"
#define ARC_SEAL_HDRNAME_LEN sizeof(ARC_SEAL_HDRNAME) - 1

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
	u_char algorithm[ARC_SEAL_MAX_SHORT_VALUE_LEN + 1];
	u_char chain_validation[ARC_SEAL_MAX_SHORT_VALUE_LEN + 1];
	u_char signature_domain[ARC_SEAL_MAX_SHORT_VALUE_LEN + 1];
	u_char signature_selector[ARC_SEAL_MAX_SHORT_VALUE_LEN + 1];
	u_char signature_time[ARC_SEAL_MAX_SHORT_VALUE_LEN + 1];
	u_char signature_value[ARC_SEAL_MAX_LONG_VALUE_LEN + 1];
};

/*
**  ARC_SEAL_PARSE -- parse an ARC-Seal: header, return a structure containing
**                    a parsed result
**
**  Parameters:
**  	hdr -- NULL-terminated contents of an ARC-Seal: header field
**  	as  -- a pointer to a (struct arcseal) loaded by values after parsing
**
**  Returns:
**  	0 on success, -1 on failure
**/

extern int arc_seal_parse __P((u_char *hdr, struct arcseal *as));

#endif /* _OPENDMARC_ARCSEAL_H_ */
