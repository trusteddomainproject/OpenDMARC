/*************************************************************************
**  Copyright (c) 2012, 2014, 2016, The Trusted Domain Project.
** 	All rights reserved.
**************************************************************************/
#include "opendmarc_internal.h"

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

/*****************************************************
**  OPENDMARC_UTIL_CLEARARGV -- Free the argv array
**
**	Parameters:
**		ary	-- Pointer to array to free
**	Returns:
**		NULL always
**	Side Effects:
**		Allocates and reallocates memory.
*/
u_char **
opendmarc_util_clearargv(u_char **ary)
{
	if (ary != NULL)
	{
		u_char **arp;

		for (arp = ary; *arp != NULL; ++arp)
		{
			(void) free(*arp);
			*arp = NULL;
		}
		(void) free(ary);
		ary = NULL;
	}
	return ary;
}

/*****************************************************
**  OPENDMARC_UTIL_PUSHARGV -- Add to and array of strings.
**
**	Parameters:
**		str	-- The string to add.
**		ary	-- The array to extend.
**		cnt	-- Points to number of elements.
**	Returns:
**		ary on success.
**		NULL on error and sets errno.
**	Side Effects:
**		Allocates and reallocates memory.
*/
u_char **
opendmarc_util_pushargv(u_char *str, u_char **ary, int *cnt)
{
	int   	 i;
	u_char **tmp;

	if (str == NULL)
		return ary;

	if (ary == NULL)
	{
		ary = malloc(sizeof(char **) * 2);
		if (ary == NULL)
		{
			return NULL;
		}
		ary[0] = strdup(str);
		ary[1] = NULL;
		if (ary[0] == NULL)
		{
			(void) free(ary);
			return NULL;
		}
		if (cnt != NULL)
			*cnt = 1;
		return ary;
	}
	if (cnt == NULL)
	{
		for (i = 0; ;i++)
		{
			if (ary[i] == NULL)
				break;
		}
	}
	else
		i = *cnt;
	tmp = realloc((void *)ary, sizeof(char **) * (i+2));
	if (tmp == NULL)
	{
		ary = opendmarc_util_clearargv(ary);
		return NULL;
	}
	ary = tmp;
	ary[i] = strdup(str);
	if (ary[i] == NULL)
	{
		ary = opendmarc_util_clearargv(ary);
		return NULL;
	}
	ary[i+1] = NULL;
	if (cnt != NULL)
		*cnt = i + 1;
	return ary;
}

/*****************************************************
**  OPENDMARC_UTIL_DUPE_ARGV -- Duplicate an argv
**
**	Parameters:
**		ary	-- Pointer to array to dupe
**	Returns:
**		u_char **	-- On success
**		NULL		-- on error
**	Side Effects:
**		Allocates and reallocates memory.
*/
u_char **
opendmarc_util_dupe_argv(u_char **ary)
{
	u_char **new = NULL;
	int      new_cnt = 0;

	if (ary != NULL)
	{
		u_char **arp;

		for (arp = ary; *arp != NULL; ++arp)
			new = opendmarc_util_pushargv(*arp, new, &new_cnt);
	}
	return new;
}

/*****************************************************
**  OPENDMARC_UTIL_CLEANUP -- Remove whitespace
**
**	Parameters:
**		str	-- The string cleanup
**		buf	-- Where to place result
**		buflen	-- Length of buf
**	Returns:
**		buf on success.
**		NULL on error and sets errno.
**	Side Effects:
*/
u_char *
opendmarc_util_cleanup(u_char *str, u_char *buf, size_t buflen)
{
	char *sp, *ep;

	if (str == NULL || buf == NULL || strlen((char *)str) > buflen)
	{
		errno = EINVAL;
		return NULL;
	}

	(void) memset(buf, '\0', buflen);

	for (sp = str, ep = buf; *sp != '\0'; sp++)
	{
		if (!isascii(*sp) || !isspace(*sp))
			*ep++ = *sp;
	}

	return buf;
}

/************************************************************
** OPENDMARC_UTIL_FINDDOMAIN --Focus on the domain
**
**	Parameters:
**		raw	-- The address containing domain
**		buf	-- Where to place result
**		buflen	-- Length of buf
**	Returns:
**		buf on success.
**		NULL on error and sets errno.
**	Side Effects:
** 	   e.g. (foo) a@a.com (bar) --->  a.com
**	        "foo" <a@a.com> "foo" --> a.com
**		a@a.com, b@b.com, c@c.com --> a.com
*/
u_char *
opendmarc_util_finddomain(u_char *raw, u_char *buf, size_t buflen)
{
	u_char *a     	= NULL;
	u_char *b     	= NULL;
	u_char *ep    	= NULL;
	u_char  copy[BUFSIZ];
	u_char *cp	= NULL;
	int 	inparen	= 0;
#define OPENDMARC_MAX_QUOTES (256)
	int	quotes[OPENDMARC_MAX_QUOTES + 1];
	int	numquotes = 0;
	size_t  len;

	if (raw == NULL)
		return NULL;

	(void) memset(copy, '\0', sizeof copy);
	len = strlen((char *)raw);
	if (len > BUFSIZ)
		len = BUFSIZ - 1;
	(void) strncpy(copy, raw, len);

	/*
	 * Quoted commas do not delimit addresses.
	 * Un-quoted ones do.
	 */
	for (cp = copy; *cp != '\0'; ++cp)
	{
		/*
		 * <> has a higher precedence than quotes.
		 * Prevents "From: Davide D'Marco <user@blah.com>" from breaking.
		 */
		if (*cp == '<')
			break;

		if (numquotes == 0 && *cp == ',')
		{
			*cp = '\0';
			break;
		}
		if (numquotes > 0 && *cp == ')')
		{
			if (quotes[numquotes-1]  == ')')
			{
				--numquotes;
				*cp = ' ';
				continue;
			}
		}
		if (*cp == '"' || *cp == '\'' || *cp == '(')
		{
			if (*cp == '(')
				*cp = ')';
			if (numquotes == 0)
			{
				quotes[numquotes] = *cp;
				++numquotes;
				*cp = ' ';
				continue;
			}
			if (*cp == quotes[numquotes -1])
			{
				--numquotes;
				*cp = ' ';
				continue;
			}
			quotes[numquotes] = *cp;
			if (numquotes >= OPENDMARC_MAX_QUOTES)
				break;
			++numquotes;
			*cp = ' ';
			continue;
		}
		if (numquotes > 0)
			*cp = ' ';
	}
	ep = copy + strlen((char *)copy);
	for (b = ep-1; b > copy; --b)
	{
		if (*b == '<')
			break;
	}
	if (*b == '<')
	{
		for (a = b; a < ep; ++a)
		{
			if (*a == '>')
				break;
		}
		if (*a == '>')
		{
			*a = '\0';
			cp = ++b;
			goto strip_local_part;
		}
	}
	for (a = copy; a < ep; a++)
	{
		if (isspace((int)*a))
			continue;
		if (*a == '(')
		{
			inparen = 1;
			continue;
		}
		if (inparen == 1 && *a != ')')
			continue;
		if (inparen == 1 && *a == ')')
		{
			inparen = 0;
			continue;
		}
		break;
	}
	for (b = ep -1; b > a; --b)
	{
		if (isspace((int)*b))
			continue;
		if (*b == ')')
		{
			inparen = 1;
			continue;
		}
		if (inparen == 1 && *b != '(')
			continue;
		if (inparen == 1 && *b == '(')
		{
			inparen = 0;
			continue;
		}
		break;
	}
	*(b+1) ='\0';
	cp = a;
strip_local_part:
	if (cp == NULL)
		cp = copy;
	ep = strchr(cp, '@');
	if (ep != NULL)
		cp = ep + 1;
	len = strlen((char *)cp);
	if (len > buflen)
		cp[buflen -1] = '\0';
	len = strlen((char *)cp);
	if (len > 0)
	{
		/*
		 * If the domain name ends in a dot, drop that dot.
		 */
		ep = cp + len -1;
		if (*ep == '.')
			*ep = '\0';
	}
	(void) strlcpy(buf, cp, buflen);
	return buf;
}

char **
opendmarc_util_freenargv(char **ary, int *num)
{
	if (ary != NULL)
	{
		char **ccp;

		for (ccp = ary; *ccp != NULL; ++ccp)
		{
			(void) free(*ccp);
			*ccp = NULL;
		}
		(void) free(ary);
		ary = NULL;
	}
	if (num != NULL)
		*num = 0;
	return NULL;
}

char **
opendmarc_util_pushnargv(char *str, char **ary, int *num)
{
	int    i;
	char **tmp;

	if (str != NULL)
	{
		if (ary == NULL)
		{
			ary = calloc(sizeof(char **), 2);
			if (ary == NULL)
			{
				if (num != NULL)
					*num = 0;
				return NULL;
			}
			*ary = strdup(str);
			*(ary+1) = NULL;
			if (*ary == NULL)
			{
				(void) free(ary);
				ary = NULL;
				if (num != NULL)
					*num = 0;
				return NULL;
			}
			if (num != NULL)
				*num = 1;
			return ary;
		}
		i = 0;
		if (num == NULL)
		{
			for (i = 0; ;i++)
			{
				if (ary[i] == NULL)
					break;
			}
		}
		else
			i = *num;
		tmp = realloc((void *)ary, sizeof(char **) * (i+2));
		if (tmp == NULL)
		{
			ary = opendmarc_util_freenargv(ary, num);
			return NULL;
		}
		ary = tmp;
		ary[i] = strdup(str);
		if (ary[i] == NULL)
		{
			ary = opendmarc_util_freenargv(ary, num);
			return NULL;
		}
		++i;
		ary[i] = NULL;
		if (num != NULL)
			*num = i;
	}
	return ary;
}

/*      
** Convert a decimal unsigned long interger into a string.
** Returns a pointer to the passed buffer.
*/
char *  
opendmarc_util_ultoa(unsigned long val, char *buffer, size_t bufferlen)
{       
	register char  *b = buffer;
	register size_t l = bufferlen;
	register unsigned long    v = val;
	register long  mod, d, digit;
#define MAXDIGITS (32)
	int digits[MAXDIGITS];

	if (b == NULL || l < 2)
		return NULL;

	if (v == 0)
	{
		*b++ = '0';
		*b = '\0';
		return buffer;
	}
	digit = 0;
	do
	{
		mod = v % 10;
		v = v / 10;
		digits[digit] = mod;
		++digit;
		if (digit >= MAXDIGITS)
			break;
	} while(v != 0);
	for (d = digit-1; d >= 0; --d)
	{
		 switch (digits[d])
		 {
			case 0: *b++ = '0'; --l; break;
			case 1: *b++ = '1'; --l; break;
			case 2: *b++ = '2'; --l; break;
			case 3: *b++ = '3'; --l; break;
			case 4: *b++ = '4'; --l; break;
			case 5: *b++ = '5'; --l; break;
			case 6: *b++ = '6'; --l; break;
			case 7: *b++ = '7'; --l; break;
			case 8: *b++ = '8'; --l; break;
			case 9: *b++ = '9'; --l; break;
		 }
		 if (l == 1)
			break;
	}
	*b = '\0';
	return buffer;
}
