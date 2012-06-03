/*************************************************************************
** $Id: opendmarc_util.c,v 1.2 2010/12/03 23:06:48 bcx Exp $
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
**************************************************************************/
#include "opendmarc_internal.h"

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
**	Returns:
**		ary on success.
**		NULL on error and sets errno.
**	Side Effects:
**		Allocates and reallocates memory.
*/
u_char **
opendmarc_util_pushargv(u_char *str, u_char **ary)
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
		return ary;
	}
	for (i = 0; ;i++)
	{
		if (ary[i] == NULL)
			break;
	}
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
	return ary;
}
