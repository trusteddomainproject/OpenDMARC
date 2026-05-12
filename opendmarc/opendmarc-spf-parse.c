/*
**  Copyright (c) 2025, The Trusted Domain Project.
**    All rights reserved.
**
**  Extracted from opendmarc.c so that the Received-SPF parser can be
**  unit tested without depending on libmilter headers.
*/

#include "build-config.h"

/* system includes */
#include <assert.h>
#include <ctype.h>
#include <string.h>

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

#include "opendmarc-spf-parse.h"

/*
**  DMARCF_PARSE_RECEIVED_SPF -- try to extract a result from a Received-SPF
**                               header field
**
**  Parameters:
**  	str -- the value of the Received-SPF field to analyze
**  	envdomain -- envelope sender domain against which to test
**
**  Return value:
**  	An ARES_RESULT_* constant.
**
**  Notes:
**  	We will not accept a result delivered via a discovered Received-SPF
**  	header field unless (a) it includes the "identity" key and its
**  	value is "mailfrom", AND (b) it includes the "envelope-from" key and
**  	its value matches the envelope sender we got via milter.  If either
**  	of those tests fails, a "pass" or a "fail" is interpreted as "neutral".
**  	This is necessary to be compliant with RFC 7489 Section 4.1,
**  	which says the SPF evaluation of MAIL FROM is what DMARC consumes.
**
**  Fix for issues #206/#221:
**  	The original parser treated any '=' as a key→value mode switch and
**  	any ';' as a pair terminator, even inside quoted strings or after
**  	the value had already started. VERP addresses (e.g.
**  	bounces+nonce=recipient@sender.example) contain '=' in the local
**  	part, which reset the value buffer mid-parse, leaving leftover bytes
**  	that corrupted the extracted domain. Two fixes:
**  	  1. Track whether we are already collecting a value (in_value); once
**  	     in value mode, '=' is just another character.
**  	  2. Honour the quoting flag for both '=' and ';' so that special
**  	     characters inside a quoted envelope-from are not misinterpreted.
*/

int
dmarcf_parse_received_spf(char *str, char *envdomain)
{
	_Bool in_result = TRUE;
	_Bool in_value  = FALSE;
	_Bool escaped   = FALSE;
	_Bool quoting   = FALSE;
	int parens = 0;
	char *p;
	char *r;
	char *end;
	char result[MAXSPFRESULT + 1];
	char spf_envdomain[BUFRSZ + 1];
	char key[BUFRSZ + 1];
	char value[BUFRSZ + 1];
	char identity[BUFRSZ + 1];

	assert(str != NULL);

	memset(spf_envdomain, '\0', sizeof spf_envdomain);
	memset(key,           '\0', sizeof key);
	memset(value,         '\0', sizeof value);
	memset(identity,      '\0', sizeof identity);
	memset(result,        '\0', sizeof result);

	/* first thing we get is the result token */
	r   = result;
	end = &result[sizeof result - 1];

	for (p = str; *p != '\0'; p++)
	{
		if (escaped)
		{
			if (parens == 0 && r < end)
				*r++ = *p;
			escaped = FALSE;
		}
		else if (*p == '\\')
		{
			escaped = TRUE;
		}
		else if (*p == '(')
		{
			parens++;
		}
		else if (*p == ')' && parens > 0)
		{
			parens--;
		}
		else if (parens == 0)
		{
			if (*p == '"')
			{
				/* entering/leaving a quoted substring */
				quoting = !quoting;
				continue;
			}

			/* a possibly meaningful character */
			if (isascii(*p) && isspace(*p))
			{
				/* a space while quoting; just continue */
				if (quoting)
					continue;

				if (in_result)
				{
					in_result = FALSE;
					r         = key;
					end       = &key[sizeof key - 1];
				}
				continue;
			}

			if (!in_result && !quoting && !in_value && *p == '=')
			{
				/* switch from key-collection to value-collection */
				memset(value, '\0', sizeof value);
				r        = value;
				end      = &value[sizeof value - 1];
				in_value = TRUE;
			}
			else if (!in_result && !quoting && *p == ';')
			{
				if (strcasecmp(key, "identity") == 0)
					strlcpy(identity, value, sizeof identity);

				if (strcasecmp(key, "envelope-from") == 0)
					strlcpy(spf_envdomain, value,
					        sizeof spf_envdomain);

				memset(key,   '\0', sizeof key);
				memset(value, '\0', sizeof value);

				r        = key;
				end      = &key[sizeof key - 1];
				in_value = FALSE;
			}
			else if (r < end)
			{
				*r++ = *p;
			}
		}
	}

	/* handle the last key=value pair (no trailing ';') */
	if (key[0] != '\0')
	{
		if (strcasecmp(key, "identity") == 0)
			strlcpy(identity, value, sizeof identity);
		if (strcasecmp(key, "envelope-from") == 0)
			strlcpy(spf_envdomain, value, sizeof spf_envdomain);
	}

	/* extract domain from envelope-from (strip local part up to '@') */
	p = strchr(spf_envdomain, '@');
	if (p != NULL)
	{
		r = spf_envdomain;
		p = p + 1;
		for (;;)
		{
			*r = *p;
			if (*p == '\0')
				break;
			r++;
			p++;
		}
	}

	if (strcasecmp(identity, "mailfrom") != 0 ||
	    strcasecmp(spf_envdomain, envdomain) != 0)
	{
		return ARES_RESULT_NEUTRAL;
	}
	else if (strcasecmp(result, "pass") == 0)
	{
		return ARES_RESULT_PASS;
	}
	else if (strcasecmp(result, "fail") == 0)
	{
		return ARES_RESULT_FAIL;
	}
	else if (strcasecmp(result, "softfail") == 0)
	{
		return ARES_RESULT_SOFTFAIL;
	}
	else if (strcasecmp(result, "neutral") == 0)
	{
		return ARES_RESULT_NEUTRAL;
	}
	else if (strcasecmp(result, "temperror") == 0)
	{
		return ARES_RESULT_TEMPERROR;
	}
	else if (strcasecmp(result, "none") == 0)
	{
		return ARES_RESULT_NONE;
	}
	else
	{
		return ARES_RESULT_PERMERROR;
	}
}
