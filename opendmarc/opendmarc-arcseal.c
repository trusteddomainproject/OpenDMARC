/*
**  Copyright (c) 2018, 2021, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <assert.h>
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

#include "opendmarc-arcseal.h"
#include "opendmarc.h"

#define OPENDMARC_ARCSEAL_MAX_FIELD_NAME_LEN 255
#define OPENDMARC_ARCSEAL_MAX_TOKEN_LEN      512

/* tables */
struct opendmarc_arcseal_lookup
{
	char *str;
	int code;
};

struct opendmarc_arcseal_lookup as_tags[] =
{
	{ "a",		AS_TAG_ALGORITHM },
	{ "cv",		AS_TAG_CHAIN_VALIDATION },
	{ "i",		AS_TAG_INSTANCE },
	{ "d",		AS_TAG_SIGNATURE_DOMAIN },
	{ "s",		AS_TAG_SIGNATURE_SELECTOR },
	{ "t",		AS_TAG_SIGNATURE_TIME },
	{ "b",		AS_TAG_SIGNATURE_VALUE },
	{ NULL,		AS_TAG_UNKNOWN }
};

/*
**  OPENDMARC_ARCSEAL_CONVERT -- convert a string to its code
**
**  Parameters:
**  	table -- in which table to look up
**  	str -- string to find
**
**  Return value:
**  	A code translation of "str".
*/

static int
opendmarc_arcseal_convert(struct opendmarc_arcseal_lookup *table, char *str)
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
**  OPENDMARC_ARCSEAL_STRIP_WHITESPACE -- removes all whitespace from a string
**                              in-place, handling a maximum string of length
**                              ARCSEAL_MAX_TOKEN_LEN
**
**  Parameters:
**  	string -- NULL-terminated string to modify
**
**  Returns:
**  	pointer to string on success, NULL on failure (max string length
**  	exceeded)
**/

static char *
opendmarc_arcseal_strip_whitespace(u_char *string)
{
	assert(string != NULL);

	int a;
	int b;
	char *string_ptr;

	string_ptr = string;

	for (a = 0, b = 0;
	     string[b] != '\0' && b < OPENDMARC_ARCSEAL_MAX_TOKEN_LEN;
	     b++)
	{
		if (isascii(string[b]) && isspace(string[b]))
			continue;

		string[a] = string[b];
		a++;
	}

	if (b >= OPENDMARC_ARCSEAL_MAX_TOKEN_LEN)
		return NULL;

	/* set remaining chars to null */
	memset(&string[a], '\0', sizeof(char) * (b - a));

	return string;
}

/*
**  OPENDMARC_ARCSEAL_PARSE -- parse an ARC-Seal: header, return a structure
**                             containing a parsed result
**
**  Parameters:
**  	hdr -- NULL-terminated contents of an ARC-Seal: header field
**  	as  -- a pointer to a (struct arcseal) loaded by values after parsing
**
**  Returns:
**  	0 on success, -1 on failure
**/

int
opendmarc_arcseal_parse(u_char *hdr, struct arcseal *as)
{
	u_char *tmp_ptr;
	u_char *token;
	u_char tmp[OPENDMARC_ARCSEAL_MAXHEADER_LEN + 1];
	int result = 0;

	tmp_ptr = tmp;

	assert(hdr != NULL);
	assert(as != NULL);

	memset(as, '\0', sizeof *as);
	memset(tmp, '\0', sizeof tmp);

	// guarantee a null-terminated string
	memcpy(tmp, hdr, MIN_OF(strlen(hdr), sizeof tmp - 1));

	while ((token = strsep((char **)&tmp_ptr, ";")) != NULL)
	{
		size_t leading_space_len;
		as_tag_t tag_code;
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
		tag_value = opendmarc_arcseal_strip_whitespace(token_ptr);
		if (tag_value == NULL)
			return -1;

		tag_code = opendmarc_arcseal_convert(as_tags, tag_label);

		switch (tag_code)
		{
		  case AS_TAG_ALGORITHM:
			strlcpy(as->algorithm, tag_value, sizeof as->algorithm);
				break;

		  case AS_TAG_CHAIN_VALIDATION:
			strlcpy(as->chain_validation, tag_value, sizeof as->chain_validation);
			break;

		  case AS_TAG_INSTANCE:
			as->instance = atoi(tag_value);
			break;

		  case AS_TAG_SIGNATURE_DOMAIN:
			strlcpy(as->signature_domain, tag_value, sizeof as->signature_domain);
			break;

		  case AS_TAG_SIGNATURE_SELECTOR:
			strlcpy(as->signature_selector, tag_value, sizeof as->signature_selector);
			break;

		  case AS_TAG_SIGNATURE_TIME:
			strlcpy(as->signature_time, tag_value, sizeof as->signature_time);
			break;

		  case AS_TAG_SIGNATURE_VALUE:
			strlcpy(as->signature_value, tag_value, sizeof as->signature_value);
			break;

		  default:
			result = -1;
			break;
		}
	}

	return result;
}
