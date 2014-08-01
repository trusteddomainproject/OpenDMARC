/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, 2014, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_ISO_LIMITS_ISO_H
# include <iso/limits_iso.h>
#endif /* HAVE_ISO_LIMITS_ISO_H */
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendmarc_strl if needed */
#ifdef USE_DMARCSTRL_H
# include <opendmarc_strl.h>
#endif /* USE_DMARCSTRL_H */

/* opendmarc includes */
#include "opendmarc.h"
#include "opendmarc-dstring.h"

/* struct dmarcf_dstring -- a dynamically-sized string */
struct dmarcf_dstring
{
	int			ds_alloc;
	int			ds_max;
	int			ds_len;
	u_char *		ds_buf;
};

/*
**  DMARCF_DSTRING_RESIZE -- resize a dynamic string (dstring)
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle
**  	len -- number of bytes desired
**
**  Return value:
**  	TRUE iff the resize worked (or wasn't needed)
**
**  Notes:
**  	This will actually ensure that there are "len" bytes available.
**  	The caller must account for the NULL byte when requesting a
**  	specific size.
*/

static _Bool
dmarcf_dstring_resize(struct dmarcf_dstring *dstr, int len)
{
	int newsz;
	u_char *new;

	assert(dstr != NULL);
	assert(len > 0);

	if (dstr->ds_alloc >= len)
		return TRUE;

	/* must resize */
	for (newsz = dstr->ds_alloc * 2;
	     newsz < len;
	     newsz *= 2)
	{
		/* impose ds_max limit, if specified */
		if (dstr->ds_max > 0 && newsz > dstr->ds_max)
		{
			if (len <= dstr->ds_max)
			{
				newsz = len;
				break;
			}

			return FALSE;
		}

		/* check for overflow */
		if (newsz > INT_MAX / 2)
		{
			/* next iteration will overflow "newsz" */
			return FALSE;
		}
	}

	new = malloc(newsz);
	if (new == NULL)
		return FALSE;

	memcpy(new, dstr->ds_buf, dstr->ds_alloc);

	free(dstr->ds_buf);

	dstr->ds_alloc = newsz;
	dstr->ds_buf = new;

	return TRUE;
}

/*
**  DMARCF_DSTRING_NEW -- make a new dstring
**
**  Parameters:
**  	dkim -- DKIM handle
**  	len -- initial number of bytes
**  	maxlen -- maximum allowed length (0 == unbounded)
**
**  Return value:
**  	A DMARCF_DSTRING handle, or NULL on failure.
*/

struct dmarcf_dstring *
dmarcf_dstring_new(int len, int maxlen)
{
	struct dmarcf_dstring *new;

	/* fail on invalid parameters */
	if ((maxlen > 0 && len > maxlen) || len == 0)
		return NULL;

	if (len < BUFRSZ)
		len = BUFRSZ;

	new = malloc(sizeof(struct dmarcf_dstring));
	if (new == NULL)
		return NULL;

	new->ds_buf = malloc(len);
	if (new->ds_buf == NULL)
	{
		free(new);
		return NULL;
	}

	memset(new->ds_buf, '\0', len);
	new->ds_alloc = len;
	new->ds_len = 0;
	new->ds_max = maxlen;

	return new;
}

/*
**  DMARCF_DSTRING_FREE -- destroy an existing dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle to be destroyed
**
**  Return value:
**  	None.
*/

void
dmarcf_dstring_free(struct dmarcf_dstring *dstr)
{
	assert(dstr != NULL);

	free(dstr->ds_buf);
	free(dstr);
}

/*
**  DMARCF_DSTRING_COPY -- copy data into a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the copy succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dmarcf_dstring_copy(struct dmarcf_dstring *dstr, u_char *str)
{
	int len;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str);

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dmarcf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* copy */
	dstr->ds_len = strlcpy((char *) dstr->ds_buf, (char *) str,
	                       dstr->ds_alloc);

	return TRUE;
}

/*
**  DMARCF_DSTRING_CAT -- append data onto a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dmarcf_dstring_cat(struct dmarcf_dstring *dstr, u_char *str)
{
	int len;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str) + dstr->ds_len;

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dmarcf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_len = strlcat((char *) dstr->ds_buf, (char *) str,
	                       dstr->ds_alloc);

	return TRUE;
}

/*
**  DMARCF_DSTRING_CAT1 -- append one byte onto a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle to update
**  	c -- input character
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dmarcf_dstring_cat1(struct dmarcf_dstring *dstr, int c)
{
	int len;

	assert(dstr != NULL);

	len = dstr->ds_len + 1;

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dmarcf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_buf[dstr->ds_len++] = c;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  DMARCF_DSTRING_CATN -- append 'n' bytes onto a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle to update
**  	str -- input string
**  	nbytes -- number of bytes to append
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dmarcf_dstring_catn(struct dmarcf_dstring *dstr, unsigned char *str,
                   size_t nbytes)
{
	size_t needed;

	assert(dstr != NULL);
	assert(str != NULL);

	needed = dstr->ds_len + nbytes;

	/* too big? */
	if (dstr->ds_max > 0 && needed >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= needed)
	{
		/* nope; try to resize */
		if (!dmarcf_dstring_resize(dstr, needed + 1))
			return FALSE;
	}

	/* append */
	memcpy(dstr->ds_buf + dstr->ds_len, str, nbytes);
	dstr->ds_len += nbytes;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  DMARCF_DSTRING_GET -- retrieve data in a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle whose string should be retrieved
**
**  Return value:
**  	Pointer to the NULL-terminated contents of "dstr".
*/

u_char *
dmarcf_dstring_get(struct dmarcf_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_buf;
}

/*
**  DMARCF_DSTRING_LEN -- retrieve length of data in a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle whose string should be retrieved
**
**  Return value:
**  	Number of bytes in a dstring.
*/

int
dmarcf_dstring_len(struct dmarcf_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_len;
}

/*
**  DMARCF_DSTRING_BLANK -- clear out the contents of a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle whose string should be cleared
**
**  Return value:
**  	None.
*/

void
dmarcf_dstring_blank(struct dmarcf_dstring *dstr)
{
	assert(dstr != NULL);

	dstr->ds_len = 0;
	dstr->ds_buf[0] = '\0';
}

/*
**  DMARCF_DSTRING_CHOP -- truncate contents of a dstring
**
**  Parameters:
**  	dstr -- DMARCF_DSTRING handle whose string should be cleared
**  	len -- length after which to clobber
**
**  Return value:
**  	None.
*/

void
dmarcf_dstring_chop(struct dmarcf_dstring *dstr, int len)
{
	assert(dstr != NULL);

	if (len < dstr->ds_len)
	{
		dstr->ds_len = len;
		dstr->ds_buf[len] = '\0';
	}
}

/*
**  DMARCF_DSTRING_PRINTF -- write variable length formatted output to a
**                           dstring
**
**  Parameters:
**  	dstr -- DMARCF_STRING handle to be updated
**  	fmt -- format
**  	... -- variable arguments
**
**  Return value:
**  	New size, or -1 on error.
*/

size_t
dmarcf_dstring_printf(struct dmarcf_dstring *dstr, char *fmt, ...)
{
	size_t len;
	size_t rem;
	va_list ap;
	va_list ap2;

	assert(dstr != NULL);
	assert(fmt != NULL);

	va_start(ap, fmt);
	va_copy(ap2, ap);
	rem = dstr->ds_alloc - dstr->ds_len;
	len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem, fmt, ap);
	va_end(ap);

	if (len > rem)
	{
		if (!dmarcf_dstring_resize(dstr, dstr->ds_len + len + 1))
		{
			va_end(ap2);
			return (size_t) -1;
		}

		rem = dstr->ds_alloc - dstr->ds_len;
		len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem,
		                fmt, ap2);
	}

	va_end(ap2);

	dstr->ds_len += len;

	return dstr->ds_len;
}
