/*************************************************************************
**  Copyright (c) 2012, 2014, The Trusted Domain Project.  All rights reserved.
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

static OPENDMARC_HASH_CTX *TLD_hctx    = NULL;
static OPENDMARC_HASH_CTX *TLDbak_hctx = NULL;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
 static pthread_mutex_t TLD_hctx_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static char TLDfile[MAXPATHLEN];

int
opendmarc_reverse_domain(u_char *domain, u_char *buf, size_t buflen)
{
	u_char *dp, *ep, *cp;
	u_char  copy[MAXDNSHOSTNAME];

	if (buf == NULL || buflen == 0 || domain == NULL)
	{
		return EINVAL;
	}


	(void) memset((char *)buf, '\0', buflen);
	/*
	 * Strip all but one leading dot.
	 */
	for (cp = domain; *cp != '\0'; ++cp)
	{
		if (*cp !=  '.')
			break;
	}
	if (strlen(cp) == 0)
	{
		return EINVAL;
	}
	if (cp > domain)
		--cp;
	(void) memset((char *)copy, '\0', sizeof copy);
	(void) strlcpy((char *)copy, cp, sizeof copy);
	ep = copy + strlen((char *)copy);

	/*
	 * Strip all trailing dots.
	 */
	for (cp = ep-1; cp > copy; --cp)
	{
		if (*cp == '.')
			*cp = '\0';
		else
			break;
	}
	ep = cp+1;
	do
	{
		for (dp = ep; dp > copy; --dp)
			if (*dp == '.')
				break;
		ep = dp;
		if (*dp == '.')
			++dp;

		strlcat((char *)buf, (char *)dp, buflen);
		if (*ep == '.')
		{
			(void) strlcat((char *)buf, ".", buflen);
			*ep = '\0';
			--ep;
		}
	} while (dp > copy && ep > copy);
	return 0;
}

/**************************************************************************************
** OPENDMARC_TLD_READ_FILE -- Read in the file of TLDs and prepare to select against it.
** Arguments:
**	path_fname	-- The path and file name to read and process
**	commentstring	-- The leading characters that comment out a line
**	drop         	-- Drop these leading characters but bind a dot to this TLD
**	except		-- Prefix that marks at TLD as a stand-alone TLD with domain.
**
** Returns:
**	0		-- On success
**	!= 0		-- On error and set's errno
** Side Effect:
**	Opens and read a file (read-only)
**	Allocates memory to store the result.
**	Be certain to call opendmarc_tld_shutdown() to free allocated memory.
**************************************************************************************/
int
opendmarc_tld_read_file(char *path_fname, char *commentstring, char *drop, char *except)
{
	FILE *	fp;
	u_char 	buf[BUFSIZ];
	char *	cp;
	void *	vp;
	int	nlines;
	int	ret;
	u_char	revbuf[MAXDNSHOSTNAME];
	int	adddot;
	int	preflen;
	OPENDMARC_HASH_CTX *hashp;

	if (path_fname == NULL)
	{
		if (*TLDfile == '\0')
			return errno = EINVAL;
		path_fname = TLDfile;
	}
	else
		(void) strlcpy(TLDfile, path_fname, sizeof TLDfile);

	if (commentstring == NULL)
		commentstring = "//";

	hashp = opendmarc_hash_init(4096 * 2);
	if (hashp == NULL)
		return (errno == 0) ? ENOMEM : errno;

	fp = fopen(path_fname, "r");
	if (fp == NULL)
		return errno;

	errno = 0;
	while (fgets((char *)buf, sizeof buf, fp) != NULL)
	{

		cp = strchr((char *)buf, '\n');
		if (cp != NULL)
			*cp = '\0';
		cp = strchr((char *)buf, '\r');
		if (cp != NULL)
			*cp = '\0';

		if (strncmp(commentstring, (char *)buf, strlen(commentstring)) == 0 || *buf == '\0')
		{
			if ((cp = strstr((char *)buf, "xn-")) != NULL)
			{
				char *ep;

				for (ep = cp; *ep != '\0';  ++ep)
				{
					if (isspace((int)*ep))
						break;
				}
				*ep = '\0';
				ret = opendmarc_reverse_domain((u_char *)cp, revbuf, sizeof revbuf);
				adddot = TRUE;
				goto got_xn;
			}
			continue;
		}
		adddot  = TRUE;
		preflen = 0;
		if (drop != NULL && strncasecmp(drop, (char *)buf, strlen(drop)) == 0)
		{
			preflen = strlen(drop);
			adddot = TRUE;
		}
		if (except != NULL && strncasecmp(except, (char *)buf, strlen(except)) == 0)
		{
			preflen = strlen(except);
			adddot = FALSE;
		}
		ret = opendmarc_reverse_domain(buf+preflen, revbuf, sizeof revbuf);
got_xn:
		if (ret != 0)
			continue;
		if (adddot == TRUE)
			(void) strlcat((char *)revbuf, ".", sizeof revbuf);

		vp = opendmarc_hash_lookup(hashp, revbuf, (void *)revbuf, strlen(revbuf));
		nlines++;
	}
	(void) fclose(fp);

# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_lock(&TLD_hctx_mutex);
# endif
	if (TLDbak_hctx != NULL)
		TLDbak_hctx = opendmarc_hash_shutdown(TLDbak_hctx);
	TLDbak_hctx = TLD_hctx;
	TLD_hctx = hashp;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_unlock(&TLD_hctx_mutex);
# endif

	return 0;
}

/**************************************************************************************
** OPENDMARC_TLD_SHUTDOWN -- Free the tld hash and return
** Arguments:
**		none 	--- void agrguments
** Returns:
**	0		-- Always
** Side Effect:
**	Frees memory
**	Locks and sets the hash to NULL
**************************************************************************************/
void
opendmarc_tld_shutdown()
{
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_lock(&TLD_hctx_mutex);
# endif
	if (TLDbak_hctx != NULL)
		TLDbak_hctx = opendmarc_hash_shutdown(TLDbak_hctx);
	if (TLD_hctx != NULL)
		TLD_hctx = opendmarc_hash_shutdown(TLD_hctx);
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_unlock(&TLD_hctx_mutex);
# endif
	return;
}

int
opendmarc_get_tld(u_char *domain, u_char *tld, size_t tld_len)
{
	int	ret;
	u_char	revbuf[MAXDNSHOSTNAME];
	u_char *rp;
	u_char  save;
	void *	vp;
	
	if (domain == NULL || tld == NULL || tld_len == 0)
		return errno = EINVAL;
	ret = opendmarc_reverse_domain(domain, revbuf, sizeof revbuf);
	if (ret != 0)
		return (errno == 0) ? EINVAL : errno;
	
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_lock(&TLD_hctx_mutex);
# endif
	vp = TLD_hctx;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_unlock(&TLD_hctx_mutex);
# endif
	if (vp == NULL)
	{
		/*
		** No tld list was supplied so copy the domain and return.
		*/
		(void) strlcpy(tld, domain, tld_len);
		return 0;
	}

	for (rp = revbuf + strlen(revbuf) -1; rp > revbuf; --rp)
	{
		if (rp == revbuf)
		{
			/* no match found in the hash table. */
			(void) strlcpy(tld, domain, tld_len);
			break;
		}
		if (*rp == '.')
		{
			save = *(rp+1);
			*(rp+1) = '\0';
# if HAVE_PTHREAD_H || HAVE_PTHREAD
			(void) pthread_mutex_lock(&TLD_hctx_mutex);
# endif
			vp = opendmarc_hash_lookup(TLD_hctx, revbuf, NULL, 0);
# if HAVE_PTHREAD_H || HAVE_PTHREAD
			(void) pthread_mutex_unlock(&TLD_hctx_mutex);
# endif
			if (vp != NULL)
			{
				*(rp+1) = save;
				(void) opendmarc_reverse_domain(revbuf, tld, tld_len);
				return 0;
			}
			*(rp+1) = save;
			*rp = '\0';
# if HAVE_PTHREAD_H || HAVE_PTHREAD
			(void) pthread_mutex_lock(&TLD_hctx_mutex);
# endif
			vp = opendmarc_hash_lookup(TLD_hctx, revbuf, NULL, 0);
# if HAVE_PTHREAD_H || HAVE_PTHREAD
			(void) pthread_mutex_unlock(&TLD_hctx_mutex);
# endif
			if (vp != NULL)
			{
				char * cp = strchr(revbuf, '.');

				if (cp == NULL)
					*rp = '.';
				(void) opendmarc_reverse_domain(revbuf, tld, tld_len);
				return 0;
			}

		}
	}
	return 0;
}
