/*
**  Copyright (c) 2018, The Trusted Domain Project.
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

#include "opendmarc-arcseal.h"

#define OPENDMARC_ARCSEAL_MAX_FIELD_NAME_LEN 255
#define OPENDMARC_ARCSEAL_MAX_TOKEN_LEN      512

#define MAX_OF(x, y) ((x) >= (y)) ? (x) : (y)
#define MIN_OF(x, y) ((x) <= (y)) ? (x) : (y)

/* tables */
struct opendmarc_arcseal_lookup
{
	char *str;
	int code;
};

struct opendmarc_arcseal_lookup tags[] =
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
**  OPENDMARC_ARCSEAL_STRIP_FIELD_NAME -- strip the field name from a string,
**                                        skipping leading whitespace
**
**  Parameters:
**  	field -- NULL-terminated string
**  	name -- NULL-terminated string containing field to remove
**  	delim -- NULL-terminated string containing delimiter
**  	buf -- destination buffer
**  	buflen -- number of bytes at buf
**
**  Returns:
**  	0 on success, -1 on failure
**/

static int
opendmarc_arcseal_strip_field_name(u_char *field, u_char *name, u_char *delim,
                                   char *buf, size_t buf_len)
{
	size_t copy_len;
	size_t name_len;
	size_t delim_len;
	size_t leading_space_len;
	size_t field_value_len;
	u_char *field_value_ptr;

	assert(field != NULL);
	assert(name != NULL);
	assert(delim != NULL);
	assert(buf != NULL);
	assert(buf_len > 0);

	name_len = strlen(name);
	delim_len = strlen(delim);

	if (name_len + delim_len > OPENDMARC_ARCSEAL_MAX_FIELD_NAME_LEN)
		return -1;

	/* build delimited name */
	u_char name_delim[OPENDMARC_ARCSEAL_MAX_FIELD_NAME_LEN + 1];
	memcpy(name_delim, (const void *)name, name_len);
	memcpy(name_delim + name_len, delim, delim_len);
	memset(name_delim + name_len + delim_len, '\0', sizeof(char));

	/* count leading spaces after field_delim */
	field_value_ptr = field + strlen(name_delim);
	leading_space_len = strspn(field_value_ptr, " ");
	field_value_ptr += leading_space_len;
	field_value_len = strlen(field_value_ptr);

	if (field_value_len > buf_len)
		return -1;

	/* copy remaining characters into buf */
	memcpy(buf, field_value_ptr, field_value_len);
	memset(buf + field_value_len, '\0', sizeof(char));

	return field_value_len;
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
	size_t tmp_size;
	u_char *tmp_ptr;
	u_char *token;
	u_char token_buf[OPENDMARC_ARCSEAL_MAX_TOKEN_LEN + 1];
	u_char tmp[tmp_size];

	tmp_size = sizeof(u_char) * OPENDMARC_ARCSEAL_MAXHEADER_LEN + 1;
	tmp_ptr = tmp;

	assert(hdr != NULL);
	assert(as != NULL);

	memset(as, '\0', sizeof *as);
	memset(tmp, '\0', tmp_size);

	// guarantee a null-terminated string
	memcpy(tmp, hdr, MIN_OF(strlen(hdr), tmp_size - 1));

	while ((token = strsep((char **)&tmp_ptr, ";")) != NULL)
	{
		size_t leading_space_len;
		as_tag_t tag_code;
		char *token_ptr;
		char *tag_label;
		char *tag_value;
		
		leading_space_len = strspn(token, " \n");
		token_ptr = token + leading_space_len;
		tag_label = strsep(&token_ptr, "=");
		tag_value = opendmarc_arcseal_strip_whitespace(token_ptr);

		tag_code = opendmarc_arcseal_convert(tags, tag_label);

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
			break;
		}
	}

	return 0;
}
