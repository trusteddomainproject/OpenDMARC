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

#include "opendmarc-arcares.h"
#include "opendmarc.h"

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
	int result = 0;
	u_char *tmp_ptr;
	u_char *token;
	u_char tmp[OPENDMARC_ARCARES_MAXHEADER_LEN + 1];

	assert(hdr != NULL);
	assert(aar != NULL);

	tmp_ptr = tmp;

	memset(aar, '\0', sizeof *aar);
	memset(tmp, '\0', sizeof tmp);

	// guarantee a null-terminated string
	memcpy(tmp, hdr, MIN(strlen(hdr), sizeof tmp - 1));

	while ((token = strsep((char **)&tmp_ptr, ";")) != NULL)
	{
		size_t leading_space_len;
		aar_tag_t tag_code;
		char *token_ptr;
		char *tag_label;
		char *tag_value;

		leading_space_len = strspn(token, " \n\t");
		token_ptr = token + leading_space_len;
		if (*token_ptr == '\0')
		        return 0;
		tag_label = strsep(&token_ptr, "=");
		tag_value = token_ptr;
		tag_code = opendmarc_arcares_convert(aar_tags, tag_label);

		switch (tag_code)
		{
		  case AAR_TAG_ARC:
			snprintf(aar->arc, sizeof aar->arc, "%s=%s", tag_label, tag_value);
			break;

		  case AAR_TAG_DKIM:
			snprintf(aar->dkim, sizeof aar->dkim, "%s=%s", tag_label, tag_value);
			break;

		  case AAR_TAG_DMARC:
			snprintf(aar->dmarc, sizeof aar->dmarc, "%s=%s", tag_label, tag_value);
			break;

		  case AAR_TAG_INSTANCE:
			aar->instance = atoi(tag_value);
			/* next value will be unlabeled authserv_id */
			if ((token = strsep((char **) &tmp_ptr, ";")) != NULL)
			{
				leading_space_len = strspn(token, " \n\t");
				tag_value = opendmarc_arcares_strip_whitespace(token);
				strlcpy(aar->authserv_id, tag_value, sizeof aar->authserv_id);
			}
			break;

		  case AAR_TAG_SPF:
			snprintf(aar->spf, sizeof aar->spf, "%s=%s", tag_label, tag_value);
			break;

		  default:
			result = -1;
			break;
		}
	}

	return result;
}

/*
** OPENDMARC_ARCARES_ARC_PARSE -- parse an ARC-Authentication-Results: header
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

int
opendmarc_arcares_arc_parse (u_char *hdr_arc, struct arcares_arc_field *arc)
{
	u_char *tmp_ptr;
	u_char *token;
	u_char tmp[OPENDMARC_ARCARES_MAXHEADER_LEN + 1];
	int result = 0;

	tmp_ptr = tmp;

	assert(hdr_arc != NULL);
	assert(arc != NULL);

	memset(arc, '\0', sizeof *arc);
	memset(tmp, '\0', sizeof tmp);

	memcpy(tmp, hdr_arc, MIN_OF(strlen(hdr_arc), sizeof tmp - 1));

	while ((token = strsep((char **)&tmp_ptr, ";")) != NULL)
	{
		size_t leading_space_len;
		aar_tag_t tag_code;
		char *token_ptr;
		char *tag_label;
		char *tag_value;

		leading_space_len = strspn(token, " \n\t");
		token_ptr = token + leading_space_len;
		if (*token_ptr == '\0')
			return 0;
		tag_label = strsep(&token_ptr, "=");
		if (token_ptr == NULL)
			return -1;
		tag_value = opendmarc_arcares_strip_whitespace(token_ptr);
		tag_code = opendmarc_arcares_convert(aar_arc_tags, tag_label);

		switch (tag_code)
		{
		  case AAR_ARC_TAG_ARC:
			strlcpy(arc->arcresult, tag_value, sizeof arc->arcresult);
			break;

		  case AAR_ARC_TAG_ARC_CHAIN:
			strlcpy(arc->arcchain, tag_value, sizeof arc->arcchain);
			break;

		  case AAR_ARC_TAG_SMTP_CLIENT_IP:
			strlcpy(arc->smtpclientip, tag_value, sizeof arc->smtpclientip);
			break;

		  default:
		  	result = -1;
			break;
		}
	}

	return result;
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
			aar->instance = aar_hdr->arcares.instance;
			strlcpy(aar->authserv_id, aar_hdr->arcares.authserv_id, sizeof aar->authserv_id);
			strlcpy(aar->arc, aar_hdr->arcares.arc, sizeof aar->arc);
			strlcpy(aar->dkim, aar_hdr->arcares.dkim, sizeof aar->dkim);
			strlcpy(aar->dmarc, aar_hdr->arcares.dmarc, sizeof aar->dmarc);
			strlcpy(aar->spf, aar_hdr->arcares.spf, sizeof aar->spf);

			return 0;
		}

		aar_hdr = aar_hdr->arcares_next;
	}

	return -1;
}
