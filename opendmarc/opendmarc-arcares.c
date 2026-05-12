/*
**  Copyright (c) 2018, 2021, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* opendmarc_strl if needed */
#ifdef USE_DMARCSTRL_H
# include <opendmarc_strl.h>
#endif /* USE_DMARCSTRL_H */

#include "opendmarc-ar.h"
#include "opendmarc-arcares.h"

#define OPENDMARC_ARCARES_MAX_FIELD_NAME_LEN 255
#define OPENDMARC_ARCARES_MAX_TOKEN_LEN      512

#ifndef MAX
# define MAX(x, y) ((x) >= (y)) ? (x) : (y)
# define MIN(x, y) ((x) <= (y)) ? (x) : (y)
#endif /* !MAX */

/* tables */
struct opendmarc_arcares_lookup
{
	char *str;
	int code;
};

struct opendmarc_arcares_lookup aar_tags[] =
{
	{ "arc",   AAR_TAG_ARC },
	{ "dkim",  AAR_TAG_DKIM },
	{ "dmarc", AAR_TAG_DMARC },
	{ "i",     AAR_TAG_INSTANCE },
	{ "spf",   AAR_TAG_SPF },
	{ NULL,    AAR_TAG_UNKNOWN }
};

struct opendmarc_arcares_lookup aar_arc_tags[] =
{
	{ "arc",            AAR_ARC_TAG_ARC },
	{ "arc.chain",      AAR_ARC_TAG_ARC_CHAIN },
	{ "smtp.client-ip", AAR_ARC_TAG_SMTP_CLIENT_IP },
	{ NULL,             AAR_ARC_TAG_UNKNOWN }
};

/*
**  OPENDMARC_ARCARES_CONVERT -- convert a string to its code
**
**  Parameters:
**  	table -- in which table to look up
**  	str -- string to find
**
**  Return value:
**  	A code translation of "str".
*/

static int
opendmarc_arcares_convert(struct opendmarc_arcares_lookup *table, char *str)
{
	int c;

	assert(table != NULL);
	assert(str != NULL);

	for (c = 0; ; c++)
	{
		if (table[c].str == NULL || strcasecmp(table[c].str, str) == 0)
			return table[c].code;
	}

	assert(0);
}

/*
**  OPENDMARC_ARCARES_STRIP_WHITESPACE -- removes all whitespace from a string
**                              in-place, handling a maximum string of length
**                              ARCARES_MAX_TOKEN_LEN
**
**  Parameters:
**  	string -- NULL-terminated string to modify
**
**  Returns:
**  	pointer to string on success, NULL on failure (max string length
**  	exceeded)
**/

static char *
opendmarc_arcares_strip_whitespace(u_char *string)
{
	assert(string != NULL);

	int a;
	int b;
	char *string_ptr;

	string_ptr = string;

	for (a = 0, b = 0;
	     string[b] != '\0' && b < OPENDMARC_ARCARES_MAX_TOKEN_LEN;
	     b++)
	{
		if (isascii(string[b]) && isspace(string[b]))
			continue;

		string[a] = string[b];
		a++;
	}

	if (b >= OPENDMARC_ARCARES_MAX_TOKEN_LEN)
		return NULL;

	/* set remaining chars to null */
	memset(&string[a], '\0', b - a);

	return string;
}

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

int
opendmarc_arcares_parse (u_char *hdr, struct arcares *aar)
{
	assert(hdr != NULL);
	assert(aar != NULL);

	return authres_parse(hdr, &(aar->payload), &(aar->instance));
}

/*
** OPENDMARC_ARCARES_ARC_PARSE -- retrieve ARC result from a parsed
**                                ARC-Authentication-Results: header result,
**                                return a structure containing ARC-specific
**                                parse result (especially client-ip)
**
** Parameters:
** 	aar -- a parse result structure populated by opendmarc_arcares_parse
** 	arc -- a pointer to a struct (arcares_arc_field) loaded by values after
**             parsing
**
**  Returns:
**  	0 on success, -1 on failure
**/

int
opendmarc_arcares_arc_parse (struct arcares *aar,
                             struct arcares_arc_field *arc)
{
	int cr;
	int cp;
	int r_found = 0;
	int p_found = 0;

	assert(aar != NULL);
	assert(arc != NULL);

	memset(arc, '\0', sizeof *arc);

	for (cr = 0; cr < aar->payload.ares_count; cr++)
	{
		if (aar->payload.ares_result[cr].result_method == ARES_METHOD_ARC)
		{
			if (r_found++)
				return -1;

			memcpy(&(arc->arcresult), &(aar->payload.ares_result[cr]),
			       sizeof arc->arcresult);

			for (cp = 0; cp < arc->arcresult.result_props; cp++)
			{
				/* old OpenARC implementations used "client-ip" */
				if (arc->arcresult.result_ptype[cp] == ARES_PTYPE_SMTP &&
				    (strcasecmp((char *) arc->arcresult.result_property[cp],
				                "remote-ip") == 0 ||
				     strcasecmp((char *) arc->arcresult.result_property[cp],
				                "client-ip") == 0))
				{
					if (p_found++)
						return -1;

					strlcpy(arc->smtpclientip,
					        (char *) arc->arcresult.result_value[cp],
					        sizeof arc->smtpclientip);
				}
			}

			if (!p_found)
				return -1;
		}
	}

	return r_found ? 0 : -1;
}

/*
**  OPENDMARC_ARCARES_LIST_PLUCK -- retrieve a struct (arcares) from a linked
**                                  list corresponding to a specified instance
**
**  Parameters:
**  	instance -- struct with instance value to find
**  	aar_hdr -- address of list head pointer (updated)
**  	aar -- a pointer to a struct (arcaar) loaded by values after parsing
**
**  Returns:
**  	0 on success, -1 on failure
*/

int
opendmarc_arcares_list_pluck(u_int instance, struct arcares_header *aar_hdr,
                             struct arcares *aar)
{
	assert(instance > 0);
	assert(aar != NULL);
	assert(aar_hdr != NULL);

	memset(aar, '\0', sizeof *aar);

	while (aar_hdr != NULL)
	{
		if (aar_hdr->arcares.instance == instance)
		{
			memcpy(aar, &(aar_hdr->arcares), sizeof *aar);
			return 0;
		}

		aar_hdr = aar_hdr->arcares_next;
	}

	return -1;
}
