/***************************************************
** $Id: opendmarc_tld.c,v 1.2 2010/12/03 23:06:48 bcx Exp $
****************************************************/

#include "opendmarc_internal.h"

char *
opendmarc_reverse_domain(char *domain, char *buf, size_t buflen)
{
	char *dp, *ep;
	char  copy[MAXDNSHOSTNAME];

	if (domain == NULL || buf == NULL || buflen == 0)
		return NULL;

	(void) memset(buf, '\0', buflen);
	(void) memset(copy, '\0', sizeof copy);
	(void) strlcpy(copy, domain, sizeof copy);
	ep = copy + strlen(copy);
	do
	{
		for (dp = ep; dp > copy; --dp)
			if (*dp == '.')
				break;
		ep = dp;
		if (*dp == '.')
			++dp;

		strlcat(buf, dp, buflen);
		if (*ep == '.')
		{
			strlcat(buf, ".", buflen);
			*ep = '\0';
			--ep;
		}
	} while (dp != copy);
	return buf;
}

/**************************************************************************************
** OPENDMARC_TLD_READ_FILE -- Read in the file of TLDs and prepare to select against it.
** Arguments:
**	path_fname	-- The path and file name to read and process
**
** Returns:
**	0		-- On success
**	!= 0		-- On error and set's errno
** Side Effect:
**	Opens and read a file (read-only)
**	Allocates memory to store the result.
**************************************************************************************/
int
opendmarc_tld_read_file(char *path_fname, char *commentstring)
{
	FILE *	fp;
	char 	buf[BUFSIZ];
	char *	cp;
	int	nlines;

	if (path_fname == NULL)
		return errno = EINVAL;

	if (commentstring == NULL)
		commentstring = "//";

	fp = fopen(path_fname, "r");
	if (fp == NULL)
		return errno;

	errno = 0;
	while (fgets(buf, sizeof buf, fp) != NULL)
	{
		if ((*buf == '/' && *(buf+1) == '/') || *buf == '\n' || *buf == '\r')
			continue;


		cp = strchr(buf, '\n');
		if (cp != NULL)
			*cp = '\0';

		for (cp = buf; *cp != '\0'; ++cp)
			if (! isascii((int)*cp))
				break;
		if (*cp != '\0')
			continue;

		nlines++;
	}
	(void) fclose(fp);

	return 0;
}

