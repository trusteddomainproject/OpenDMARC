/*************************************************************************
** The user interface to the rest of this library.
**
**  Copyright (c) 2012-2016, The Trusted Domain Project.  All rights reserved.
**************************************************************************/

#include "opendmarc_internal.h"
#include "dmarc.h"

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

/**************************************************************************
** OPENDMARC_POLICY_LIBRARY_INIT -- Initialize The Library
**	Parameters:
**		lib_init	-- Address of a filled in DMARC_LIB_T structure
**	Returns:
**		DMARC_PARSE_OKAY		-- on success
**		DMARC_PARSE_ERROR_NULL_CTX	-- if lib_init is null
**		DMARC_TLD_ERROR_UNKNOWN		-- If lip_init->tld_type is undefined
**	Side Effects:
**		Sets a global pointer
**	Warning:
**		This function is not thread safe so only call once on
**		startup.
***************************************************************************/
static OPENDMARC_LIB_T *Opendmarc_Libp = NULL;
static OPENDMARC_LIB_T Opendmarc_Lib;

OPENDMARC_STATUS_T
opendmarc_policy_library_init(OPENDMARC_LIB_T *lib_init)
{
	int ret = DMARC_PARSE_OKAY;

	if (lib_init == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	(void) memcpy(&Opendmarc_Lib, lib_init, sizeof(OPENDMARC_LIB_T));
	Opendmarc_Libp = &Opendmarc_Lib;
	errno = 0;
	if ((Opendmarc_Libp->tld_source_file)[0] != '\0')
	{
		switch (Opendmarc_Libp->tld_type)
		{
			case OPENDMARC_TLD_TYPE_MOZILLA:
				ret = opendmarc_tld_read_file(Opendmarc_Libp->tld_source_file,
						"//", "*.", "!");
				if (ret != 0)
					ret = errno;
				break;
			default:
				return DMARC_TLD_ERROR_UNKNOWN;
		}
	}
	return ret;
}

/**************************************************************************
** OPENDMARC_POLICY_LIBRARY_SHUTDOWN -- Shutdown The Libarary
**	Parameters:
**		lib_init	-- The prior DMARC_LIB_T strucgture
**	Returns:
**		DMARC_PARSE_OKAY		-- always
**	Side Effects:
**		May free memory
**	Warning:
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_library_shutdown(OPENDMARC_LIB_T *lib_init)
{
	(void) opendmarc_tld_shutdown();
	return DMARC_PARSE_OKAY;
}

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_INIT -- Get policy context for connection
**	Parameters:
**		ip_addr	-- An IP addresss in string form.
**		is_ipv6 -- Zero for IPv4, non-zero for IPv6
**	Returns:
**		pctx 	-- An allocated and initialized context pointer.
**		NULL	-- On failure and sets errno
**	Side Effects:
**		Allocates memory.
***************************************************************************/
DMARC_POLICY_T *
opendmarc_policy_connect_init(u_char *ip_addr, int is_ipv6)
{
	DMARC_POLICY_T *pctx;
	int		xerrno;

	if (ip_addr == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	pctx = malloc(sizeof(DMARC_POLICY_T));
	if (pctx == NULL)
	{
		return NULL;
	}
	(void) memset(pctx, '\0', sizeof(DMARC_POLICY_T));
	pctx->p = DMARC_RECORD_P_UNSPECIFIED;
	pctx->sp = DMARC_RECORD_P_UNSPECIFIED;
	pctx->ip_addr = (u_char *)strdup((char *)ip_addr);
	if (pctx->ip_addr == NULL)
	{
		xerrno = errno;
		(void) free(pctx);
		errno = xerrno;
		return NULL;
	}
	if (is_ipv6 == 0)
		pctx->ip_type = DMARC_POLICY_IP_TYPE_IPV4;
	else
		pctx->ip_type = DMARC_POLICY_IP_TYPE_IPV6;
	return pctx;
}

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_CLEAR -- Zero the policy context but doesn't
**					free it
**
**	Parameters:
**		pctx	-- The context to zero.
**	Returns:
**		pctx 	-- Zeroed but still allocated context
**		NULL	-- On failure and sets errno
**	Side Effects:
**		Frees memory.
***************************************************************************/
DMARC_POLICY_T *
opendmarc_policy_connect_clear(DMARC_POLICY_T *pctx)
{
	if (pctx == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	if (pctx->ip_addr != NULL)
		(void) free(pctx->ip_addr);
	if (pctx->from_domain != NULL)
		(void) free(pctx->from_domain);
	if (pctx->spf_domain != NULL)
		(void) free(pctx->spf_domain);
	if (pctx->dkim_domain != NULL)
		(void) free(pctx->dkim_domain);
	if (pctx->spf_human_outcome != NULL)
		(void) free(pctx->spf_human_outcome);
	if (pctx->dkim_human_outcome != NULL)
		(void) free(pctx->dkim_human_outcome);
	if (pctx->organizational_domain != NULL)
		(void) free(pctx->organizational_domain);
	pctx->rua_list = opendmarc_util_clearargv(pctx->rua_list);
	pctx->rua_cnt  = 0;
	pctx->ruf_list = opendmarc_util_clearargv(pctx->ruf_list);
	pctx->ruf_cnt  = 0;
	pctx->fo       = 0;

	(void) memset(pctx, '\0', sizeof(DMARC_POLICY_T));
	pctx->p   = DMARC_RECORD_P_UNSPECIFIED;
	return pctx;
}

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_RSET -- Rset for another message
**	Usefull if there is more than a single envelope per connection.
**	Usefull during an SMTP  RSET
**
**	Parameters:
**		pctx	-- The context to rset.
**	Returns:
**		pctx 	-- RSET context
**		NULL	-- On failure and sets errno
**	Side Effects:
**		Frees memory.
**		Preserves the IP address and type
***************************************************************************/
DMARC_POLICY_T *
opendmarc_policy_connect_rset(DMARC_POLICY_T *pctx)
{
	u_char *ip_save;
	int     ip_type;

	if (pctx == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	ip_save       = pctx->ip_addr;
	pctx->ip_addr = NULL;
	ip_type       = pctx->ip_type;
	pctx->ip_type = -1;

	pctx = opendmarc_policy_connect_clear(pctx);

	if (pctx == NULL)
		return NULL;
	pctx->ip_addr = ip_save;
	pctx->ip_type = ip_type;
	return pctx;
}

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_SHUTDOWN -- Free the policy context
**	Frees and deallocates the context
**
**	Parameters:
**		pctx	-- The context to free and deallocate.
**	Returns:
**		NULL	-- Always
**	Side Effects:
**		Frees memory.
***************************************************************************/
DMARC_POLICY_T *
opendmarc_policy_connect_shutdown(DMARC_POLICY_T *pctx)
{
	if (pctx != NULL)
	{
		pctx = opendmarc_policy_connect_clear(pctx);
		(void) free(pctx);
		pctx = NULL;
	}
	return pctx;
}

int
opendmarc_policy_check_alignment(u_char *subdomain, u_char *tld, int mode)
{
	u_char rev_sub[512];
	u_char rev_tld[512];
	u_char tld_buf[512];
	u_char *ep;
	int	ret;

	if (subdomain == NULL)
		return EINVAL;
	if (tld == NULL)
		return EINVAL;

	if (mode== DMARC_RECORD_A_UNSPECIFIED)
		mode= DMARC_RECORD_A_RELAXED;

	(void) memset(tld_buf, '\0', sizeof tld_buf);
	(void) strlcpy(tld_buf, tld, sizeof tld_buf);

	(void) memset(rev_sub, '\0', sizeof rev_sub);
	(void) opendmarc_reverse_domain(subdomain, rev_sub, sizeof rev_sub);
	ep = rev_sub + strlen(rev_sub) -1;
	if (*ep != '.')
		(void) strlcat((char *)rev_sub, ".", sizeof rev_sub);

	(void) memset(rev_tld, '\0', sizeof rev_tld);
	(void) opendmarc_reverse_domain(tld_buf,   rev_tld, sizeof rev_tld);
	ep = rev_tld + strlen(rev_tld) -1;
	if (*ep != '.')
		(void) strlcat((char *)rev_tld, ".", sizeof rev_tld);

	/*
	 * Perfect match is aligned irrespective of relaxed or strict.
	 */
	if (strcasecmp(rev_tld, rev_sub) == 0)
		return 0;

	ret = strncasecmp(rev_tld, rev_sub, strlen(rev_tld));
	if (ret == 0 && mode == DMARC_RECORD_A_RELAXED)
			return 0;

        ret = strncasecmp(rev_sub, rev_tld, strlen(rev_sub));
        if (ret == 0 && mode == DMARC_RECORD_A_RELAXED)
                        return 0;

	ret = opendmarc_get_tld(tld, tld_buf, sizeof tld_buf);
	if (ret != 0)
		return -1;
	(void) memset(rev_tld, '\0', sizeof rev_tld);
	(void) opendmarc_reverse_domain(tld_buf,   rev_tld, sizeof rev_tld);
	ep = rev_tld + strlen(rev_tld) -1;
	if (*ep != '.')
		(void) strlcat((char *)rev_tld, ".", sizeof rev_tld);

	/*
	 * Perfect match is aligned irrespective of relaxed or strict.
	 */
	if (strcasecmp(rev_tld, rev_sub) == 0)
		return 0;

	ret = strncasecmp(rev_tld, rev_sub, strlen(rev_tld));
	if (ret == 0 && mode == DMARC_RECORD_A_RELAXED)
			return 0;

        ret = strncasecmp(rev_sub, rev_tld, strlen(rev_sub));
        if (ret == 0 && mode == DMARC_RECORD_A_RELAXED)
                        return 0;
	return -1;
}

/**************************************************************************
** OPENDMARC_POLICY_STORE_FROM_DOMAIN -- Store domain from the From: header.
** 	If the domain is an address parse the domain from it.
**	The domain is needed to perform alignment checks.

**	Parameters:
**		pctx		-- The context to uptdate
**		from_domain 	-- A string
**	Returns:
**		DMARC_PARSE_OKAY		-- On success
**		DMARC_PARSE_ERROR_NULL_CTX	-- If pctx was NULL
**		DMARC_PARSE_ERROR_EMPTY		-- if from_domain NULL or zero
**		DMARC_PARSE_ERROR_NO_DOMAIN	-- No domain in from_domain
**	Side Effects:
**		Allocates memory.
**	Note:
**		Does not check to insure that the found domain is a
**		syntactically valid domain. It is okay for domain to
**		puney decoded into 8-bit data.
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_store_from_domain(DMARC_POLICY_T *pctx, u_char *from_domain)
{
	char domain_buf[256];
	char *dp;

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (from_domain == NULL || strlen((char *)from_domain) == 0)
		return DMARC_PARSE_ERROR_EMPTY;
	dp = opendmarc_util_finddomain(from_domain, domain_buf, sizeof domain_buf);
	if (dp == NULL)
		return DMARC_PARSE_ERROR_NO_DOMAIN;
	pctx->from_domain = strdup((char *)dp);
	if (pctx->from_domain == NULL)
		return DMARC_PARSE_ERROR_NO_ALLOC;
	return DMARC_PARSE_OKAY;
}

/**************************************************************************
** OPENDMARC_POLICY_STORE_SPF -- Store spf results
**	Okay to supply the raw MAIL From: data
**
**	Parameters:
**		pctx	-- The context to uptdate
**		domain 	-- The domain used to verify SPF
**		result 	-- DMARC_POLICY_SPF_OUTCOME_NONE
**			or DMARC_POLICY_SPF_OUTCOME_PASS
**			or DMARC_POLICY_SPF_OUTCOME_FAIL
**			or DMARC_POLICY_SPF_OUTCOME_TMPFAIL
**		origin 	-- DMARC_POLICY_SPF_ORIGIN_MAILFROM 
**			or DMARC_POLICY_SPF_ORIGIN_HELO
**		human_readable -- A human readable reason for failure
**	Returns:
**		DMARC_PARSE_OKAY		-- On success
**		DMARC_PARSE_ERROR_NULL_CTX	-- If pctx was NULL
**		DMARC_PARSE_ERROR_EMPTY		-- if domain NULL or zero
**		DMARC_PARSE_ERROR_NO_DOMAIN	-- No domain in domain
**	Side Effects:
**		Allocates memory.
**	Note:
**		Does not check to insure that the domain is a
**		syntactically valid domain. It is okay for domain to
**		puney decoded into 8-bit data.
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_store_spf(DMARC_POLICY_T *pctx, u_char *domain, int result, int origin, u_char *human_readable)
{
	char domain_buf[256];
	char *dp;

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (domain == NULL || strlen((char *)domain) == 0)
		return DMARC_PARSE_ERROR_EMPTY;
	dp = opendmarc_util_finddomain(domain, domain_buf, sizeof domain_buf);
	if (dp == NULL)
		return DMARC_PARSE_ERROR_NO_DOMAIN;
	if (human_readable != NULL)
		pctx->spf_human_outcome = strdup((char *)human_readable);
	pctx->spf_domain = strdup((char *)dp);
	if (pctx->spf_domain == NULL)
		return DMARC_PARSE_ERROR_NO_ALLOC;
	switch (result)
	{
		case DMARC_POLICY_SPF_OUTCOME_NONE:
		case DMARC_POLICY_SPF_OUTCOME_PASS:
		case DMARC_POLICY_SPF_OUTCOME_FAIL:
		case DMARC_POLICY_SPF_OUTCOME_TMPFAIL:
			pctx->spf_outcome = result;
			break;
		default:
			return DMARC_PARSE_ERROR_BAD_SPF_MACRO;
	}
	switch (origin)
	{
		case DMARC_POLICY_SPF_ORIGIN_MAILFROM:
		case DMARC_POLICY_SPF_ORIGIN_HELO:
			pctx->spf_origin = origin;
			break;
		default:
			return DMARC_PARSE_ERROR_BAD_SPF_MACRO;
	}
	return DMARC_PARSE_OKAY;
}


/**************************************************************************
** OPENDMARC_POLICY_STORE_DKIM -- Store dkim results
**
**	Parameters:
**		pctx		-- The context to uptdate
**		d_equal_domain 	-- The the domain from the p= 
**		dkim_result 	-- DMARC_POLICY_DKIM_OUTCOME_NONE
**				or DMARC_POLICY_DKIM_OUTCOME_PASS
**				or DMARC_POLICY_DKIM_OUTCOME_FAIL
**				or DMARC_POLICY_DKIM_OUTCOME_TMPFAIL
**		human_result	-- A human readable reason for failure
**	Returns:
**		DMARC_PARSE_OKAY		-- On success
**		DMARC_PARSE_ERROR_NULL_CTX	-- If pctx was NULL
**		DMARC_PARSE_ERROR_EMPTY		-- if domain NULL or zero
**		DMARC_PARSE_ERROR_NO_DOMAIN	-- No domain in domain
**		DMARC_PARSE_ERROR_NO_ALLOC	-- Memory allocation failed
**	Side Effects:
**		Allocates memory.
**	Note:
**		Does not check to insure that the domain is a
**		syntactically valid domain. It is okay for domain to
**		puney decoded into 8-bit data.
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_store_dkim(DMARC_POLICY_T *pctx, u_char *d_equal_domain, int dkim_result, u_char *human_result)
{
	char	domain_buf[256];
	u_char *dp;
	int	result = DMARC_POLICY_DKIM_OUTCOME_NONE;

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (d_equal_domain == NULL || strlen((char *)d_equal_domain) == 0)
		return DMARC_PARSE_ERROR_EMPTY;

	switch (dkim_result)
	{
		case DMARC_POLICY_DKIM_OUTCOME_NONE:
		case DMARC_POLICY_DKIM_OUTCOME_PASS:
		case DMARC_POLICY_DKIM_OUTCOME_FAIL:
		case DMARC_POLICY_DKIM_OUTCOME_TMPFAIL:
			result = dkim_result;
			break;
		default:
			return DMARC_PARSE_ERROR_BAD_DKIM_MACRO;
	}
	if (pctx->dkim_final == TRUE)
		return DMARC_PARSE_OKAY;

	dp = opendmarc_util_finddomain(d_equal_domain, domain_buf, sizeof domain_buf);
	if (dp == NULL || strlen(dp) == 0)
		return DMARC_PARSE_ERROR_NO_DOMAIN;

	/*
	 * If the d= domain is an exact match to the from_domain
	 * select this one as the domain of choice.
	 * If the outcome is pass, the is the final choice.
	 */
	if (strcasecmp((char *)dp, pctx->from_domain) == 0)
	{
		if (pctx->dkim_domain != NULL)
		{
			(void) free(pctx->dkim_domain);
			pctx->dkim_domain = NULL;
		}
		if (result == DMARC_POLICY_DKIM_OUTCOME_PASS)
		{
			pctx->dkim_final = TRUE;
			goto set_final;
		}
		if (pctx->dkim_outcome == DMARC_POLICY_DKIM_OUTCOME_PASS)
			return DMARC_PARSE_OKAY;
		goto set_final;
	}

	/*
	 * See if the d= is a superset of the from domain.
	 * If so and if we have not already found
	 * a best match, make this the temporary best match.
	 */
	if (opendmarc_policy_check_alignment(dp, pctx->from_domain,
	                                     pctx->adkim) == 0)
	{
		if (pctx->dkim_domain != NULL)
		{
			(void) free(pctx->dkim_domain);
			pctx->dkim_domain = NULL;
		}
		if (result == DMARC_POLICY_DKIM_OUTCOME_PASS)
			goto set_final;
	}
	/*
	 * If we found any record so far that passed.
	 * preserve it.
	 */
	if (pctx->dkim_outcome == DMARC_POLICY_DKIM_OUTCOME_PASS)
		return DMARC_PARSE_OKAY;

set_final:
	if (pctx->dkim_domain == NULL)
		pctx->dkim_domain = strdup((char *)dp);
	if (pctx->dkim_domain == NULL)
		return DMARC_PARSE_ERROR_NO_ALLOC;
	if (human_result != NULL)
	{
		if (pctx->dkim_human_outcome != NULL)
			(void) free(pctx->dkim_human_outcome);
		pctx->dkim_human_outcome = strdup((char *)human_result);
	}
	pctx->dkim_outcome = result;
	return DMARC_PARSE_OKAY;
}

/**************************************************************************
** OPENDMARC_POLICY_QUERY_DMARC_XDOMAIN -- Verify that we have permission
**										to send to domain
**	Parameters:
**		pctx	-- The context to uptdate
**		uri		-- URI listed in DMARC record
**	Returns:
**		DMARC_PARSE_OKAY		-- On success, and fills pctx
**		DMARC_PARSE_ERROR_NULL_CTX	-- If pctx was NULL
**		DMARC_PARSE_ERROR_EMPTY		-- if domain NULL or zero
**		DMARC_PARSE_ERROR_NO_DOMAIN	-- No domain in domain
**		DMARC_DNS_ERROR_TMPERR		-- No domain, try again later
**		DMARC_DNS_ERROR_NO_RECORD	-- No DMARC record found.
**	Side Effects:
**		Performs one or more DNS lookups
** 
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_query_dmarc_xdomain(DMARC_POLICY_T *pctx, u_char *uri)
{
	u_char buf[BUFSIZ];
	u_char copy[256];
	u_char domain[256];
	u_char domain_tld[256];
	u_char uri_tld[256];
	u_char *ret = NULL;
	int dns_reply = 0;
	int i = 0;
	int err = 0;

	if (pctx == NULL || pctx->from_domain == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;

	if (uri == NULL)
		return DMARC_PARSE_ERROR_EMPTY;

	memset(buf, '\0', sizeof buf);
	memset(copy, '\0', sizeof copy);
	memset(domain, '\0', sizeof domain);
	memset(domain_tld, '\0', sizeof domain_tld);
	memset(uri_tld, '\0', sizeof uri_tld);

	/* Get out domain from our URI */
	if (strncasecmp(uri, "mailto:", 7) == 0)
		uri += 7;

	if (opendmarc_util_finddomain(uri, domain, sizeof domain) == NULL)
		return DMARC_PARSE_ERROR_NO_DOMAIN;

	/* Ensure that we're not doing a cross-domain check */
	err = 0;
	err = opendmarc_get_tld(domain, uri_tld, sizeof uri_tld);
	err += opendmarc_get_tld(pctx->from_domain, domain_tld, sizeof domain_tld);
	if (err != 0)
		return DMARC_DNS_ERROR_NO_RECORD;

	if (strncasecmp((char *) uri_tld, (char *) domain_tld,
	                sizeof uri_tld) == 0)
		return DMARC_PARSE_OKAY;

	strlcpy((char *) copy, (char *) pctx->from_domain, sizeof copy);
	strlcat((char *) copy, "._report._dmarc.", sizeof copy);
	strlcat((char *) copy, (char *) domain, sizeof copy);

	/* Query DNS */
	for (i = 0; i < DNS_MAX_RETRIES && ret == NULL; i++)
	{
		ret = (u_char *) dmarc_dns_get_record((char *) copy, &dns_reply,
		                                      (char *) buf, sizeof buf);
		if (ret != 0 || dns_reply == HOST_NOT_FOUND)
			break;

		/* requery if didn't resolve CNAME */
		if (ret == NULL && *buf != '\0')
		{
			strlcpy((char *) copy, (char *) buf, sizeof copy);
			continue;
		}
	}
	if (dns_reply == NETDB_SUCCESS && buf != NULL)
	{
		/* Must include DMARC version */
		if (strncasecmp((char *)buf, "v=DMARC1", sizeof buf) == 0)
		{
			return DMARC_PARSE_OKAY;
		}
	}

	/*
	** Retry with a * literal.
	*/
	strlcpy((char *) copy, (char *) "*", sizeof copy);
	strlcat((char *) copy, "._report._dmarc.", sizeof copy);
	strlcat((char *) copy, (char *) domain, sizeof copy);
	for (i = 0; i < DNS_MAX_RETRIES && ret == NULL; i++)
	{
		ret = (u_char *) dmarc_dns_get_record((char *) copy, &dns_reply,
		                                      (char *) buf, sizeof buf);
		if (ret != 0 || dns_reply == HOST_NOT_FOUND)
			break;

		/* requery if didn't resolve CNAME */
		if (ret == NULL && *buf != '\0')
		{
			strlcpy((char *) copy, (char *) buf, sizeof copy);
			continue;
		}
	}
	if (dns_reply == NETDB_SUCCESS && buf != NULL)
	{
		/* Must include DMARC version */
		if (strncasecmp((char *)buf, "v=DMARC1", sizeof buf) == 0)
		{
			return DMARC_PARSE_OKAY;
		}
		else
		{
			return DMARC_DNS_ERROR_NO_RECORD;
		}
	}

	switch (dns_reply)
	{
		case HOST_NOT_FOUND:
		case NO_DATA:
		case NO_RECOVERY:
			return DMARC_DNS_ERROR_NO_RECORD;
		case TRY_AGAIN:
		case NETDB_INTERNAL:
			return DMARC_DNS_ERROR_TMPERR;
		default:
			return DMARC_DNS_ERROR_NO_RECORD;
	}
}

/**************************************************************************
** OPENDMARC_POLICY_QUERY_DMARC -- Look up the _dmarc record for the 
**					specified domain. If not found
**				  	try the organizational domain.
**	Parameters:
**		pctx	-- The context to uptdate
**		domain 	-- The domain for which to lookup the DMARC record
**	Returns:
**		DMARC_PARSE_OKAY		-- On success, and fills pctx
**		DMARC_PARSE_ERROR_NULL_CTX	-- If pctx was NULL
**		DMARC_PARSE_ERROR_EMPTY		-- if domain NULL or zero
**		DMARC_PARSE_ERROR_NO_DOMAIN	-- No domain in domain
**		DMARC_DNS_ERROR_NXDOMAIN	-- No domain found in DNS
**		DMARC_DNS_ERROR_TMPERR		-- No domain, try again later
**		DMARC_DNS_ERROR_NO_RECORD	-- No DMARC record found.
**	Side Effects:
**		Performs one or more DNS lookups
**		Allocates memory.
**	Note:
**		Does not check to insure that the domain is a
**		syntactically valid domain.
**		Looks up domain first. If that fails, finds the tld and
**		looks up topmost domain under tld. If this later is found
**		updates pctx->organizational_domain with the result.
**	Warning:
**		If no TLD file has been loaded, will silenty not do that
**		fallback lookup.
** 
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_query_dmarc(DMARC_POLICY_T *pctx, u_char *domain)
{
	u_char 		buf[BUFSIZ];
	u_char 		copy[256];
	u_char 		tld[256];
	u_char *	bp = NULL;
	int		dns_reply = 0;
	int		tld_reply = 0;
	int		loop_count = DNS_MAX_RETRIES;

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (domain == NULL || strlen(domain) == 0)
	{
		if (pctx->from_domain != NULL)
			domain = pctx->from_domain;
		else
			return DMARC_PARSE_ERROR_EMPTY;
	}

	(void) strlcpy(copy, "_dmarc.", sizeof copy);
	(void) strlcat(copy, domain, sizeof copy);

query_again:
	(void) memset(buf, '\0', sizeof buf);
	bp = dmarc_dns_get_record(copy, &dns_reply, buf, sizeof buf);
	if (bp != NULL)
	{
		if (dns_reply != HOST_NOT_FOUND)
			goto got_record;
	}
	/*
	 * Was a CNAME was found that the resolver did
	 * not follow on its own?
	 */
	if (bp == NULL && *buf != '\0')
	{
		(void) strlcpy(copy, buf, sizeof copy);
		if (--loop_count != 0)
			goto query_again;
	}

	(void) memset(tld, '\0', sizeof tld);
	tld_reply = opendmarc_get_tld(domain, tld, sizeof tld);
	if (tld_reply != 0)
		goto dns_failed;
	if (strlen(tld) > 0)
	{
		pctx->organizational_domain = strdup(tld);

		loop_count = DNS_MAX_RETRIES;
		(void) strlcpy(copy, "_dmarc.", sizeof copy);
		(void) strlcat(copy, tld, sizeof copy);
query_again2:
		(void) memset(buf, '\0', sizeof buf);
		bp = dmarc_dns_get_record(copy, &dns_reply, buf, sizeof buf);
		if (bp != NULL)
			goto got_record;
		/*
		 * Was a CNAME was found that the resolver did
		 * not follow on its own?
		 */
		if (bp == NULL && *buf != '\0')
		{
			(void) strlcpy(copy, buf, sizeof copy);
			if (--loop_count != 0)
				goto query_again2;
		}
	}
dns_failed:
	switch (dns_reply)
	{
		case HOST_NOT_FOUND:
		case NO_DATA:
		case NO_RECOVERY:
			return DMARC_DNS_ERROR_NO_RECORD;
		case TRY_AGAIN:
		case NETDB_INTERNAL:
			return DMARC_DNS_ERROR_TMPERR;
		default:
			return DMARC_DNS_ERROR_NO_RECORD;

	}
got_record:
	return opendmarc_policy_parse_dmarc(pctx, domain, buf);
}

/**************************************************************************
** OPENDMARC_GET_POLICY_TO_ENFORCE -- What to do with this message. i.e. allow
**				possible delivery, quarantine, or reject.
**	Parameters:
**		pctx	-- A Policy context
**	Returns:
**		DMARC_PARSE_ERROR_NULL_CTX	-- pctx == NULL
**		DMARC_POLICY_ABSENT		-- No DMARC record found
**		DMARC_FROM_DOMAIN_ABSENT	-- No From: domain
**		DMARC_POLICY_NONE		-- Accept if other policy allows
**		DMARC_POLICY_REJECT		-- Policy advises to reject the message
**		DMARC_POLICY_QUARANTINE		-- Policy advises to quarantine the message
**		DMARC_POLICY_PASS		-- Policy advises to accept the message
**	Side Effects:
**		Checks for domain alignment.
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_get_policy_to_enforce(DMARC_POLICY_T *pctx)
{

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;

	if (pctx->p == DMARC_RECORD_P_UNSPECIFIED)
		return DMARC_POLICY_ABSENT;

	if (pctx->from_domain == NULL)
		return DMARC_FROM_DOMAIN_ABSENT;

	pctx->dkim_alignment = DMARC_POLICY_DKIM_ALIGNMENT_FAIL;
	pctx->spf_alignment  = DMARC_POLICY_SPF_ALIGNMENT_FAIL;

	/* check for DKIM alignment */
	if (pctx->dkim_domain != NULL && pctx->dkim_outcome == DMARC_POLICY_DKIM_OUTCOME_PASS)
	{
		if (opendmarc_policy_check_alignment(pctx->from_domain, pctx->dkim_domain, pctx->adkim) == 0)
			pctx->dkim_alignment = DMARC_POLICY_DKIM_ALIGNMENT_PASS;
	}

	/* check for SPF alignment */
	if (pctx->spf_domain != NULL && pctx->spf_outcome == DMARC_POLICY_SPF_OUTCOME_PASS)
	{
		if (opendmarc_policy_check_alignment(pctx->from_domain, pctx->spf_domain, pctx->aspf) == 0)
			pctx->spf_alignment = DMARC_POLICY_SPF_ALIGNMENT_PASS;
	}

	/*
	 * If dkim passes and dkim aligns OR spf passes and spf aligns
	 * Accept the message.
	 */
	if (pctx->spf_alignment == DMARC_POLICY_SPF_ALIGNMENT_PASS ||
	    pctx->dkim_alignment == DMARC_POLICY_DKIM_ALIGNMENT_PASS)
		return DMARC_POLICY_PASS;

	if (pctx->organizational_domain != NULL)
	{
		switch (pctx->sp)
		{
		  case DMARC_RECORD_P_REJECT:
			return DMARC_POLICY_REJECT;

		  case DMARC_RECORD_P_QUARANTINE:
			return DMARC_POLICY_QUARANTINE;

		  case DMARC_RECORD_P_NONE:
			return DMARC_POLICY_NONE;
		}
	}

	switch (pctx->p)
	{
		case DMARC_RECORD_P_REJECT:
			return DMARC_POLICY_REJECT;
		case DMARC_RECORD_P_QUARANTINE:
			return DMARC_POLICY_QUARANTINE;
		case DMARC_RECORD_P_NONE:
			return DMARC_POLICY_NONE;
		default:
			/* XXX -- shouldn't be possible */
			return DMARC_POLICY_PASS;
	}
}

/*******************************************************************************
**  OPENDMARC_PARSE_DMARC -- Parse a DMARC record
**
**	Parameters:
**		pctx	-- A Policy context
**		domain  -- The domain looked up to get this DMARC record
**		record	-- The DMARC record to parse
**	Returns:
**		DMARC_PARSE_ERROR_EMPTY 	-- if any argument is NULL
**		DMARC_PARSE_ERROR_BAD_VERSION	-- if v= was bad
**		DMARC_PARSE_ERROR_BAD_VALUE	-- if value following = was bad
**		DMARC_PARSE_ERROR_NO_REQUIRED_P -- if p= was absent
**		DMARC_PARSE_OKAY		-- On Success
**	Side Effects:
**		Allocates memory.
*********************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_parse_dmarc(DMARC_POLICY_T *pctx, u_char *domain, u_char *record)
{
	u_char *cp, *eqp, *ep, *sp, *vp;
	u_char copy[BUFSIZ];
	u_char cbuf[512];
	u_char vbuf[512];

	if (pctx == NULL || domain == NULL || record == NULL || strlen((char *)record) == 0)
	{
		return DMARC_PARSE_ERROR_EMPTY;
	}
	/*
	 * Set the defaults to detect missing required items.
	 */
	pctx->pct = -1;
	pctx->ri  = -1;

	(void) memset((char *)copy, '\0', sizeof copy);
	(void) strlcpy((char *)copy, (char *)record, sizeof copy);
	ep = copy + strlen((char *)copy);


	for (cp = copy; cp != NULL && cp <= ep; )
	{
		sp = (u_char *)strchr(cp, ';');
		if (sp != NULL)
			*sp++ = '\0';
		eqp = (u_char *)strchr((char *)cp, '=');
		if (eqp == NULL)
		{
			cp = sp;
			continue;
		}
		*eqp = '\0';
		vp = eqp + 1;
			
		cp = opendmarc_util_cleanup(cp, cbuf, sizeof cbuf);
		if (cp == NULL || strlen((char *)cp) == 0)
		{
			cp = sp;
			continue;
		}
		vp = opendmarc_util_cleanup(vp, vbuf, sizeof vbuf);
		if (vp == NULL || strlen((char *)vp) == 0)
		{
			cp = sp;
			continue;
		}
		/*
		 * cp nwo points to the token, and
		 * vp now points to the token's value 
		 * both with all surronding whitepace removed.
		 */
		if (strcasecmp((char *)cp, "v") == 0)
		{
			/*
			 * Yes, this is required to be first, but why
			 * reject it if it is not first?
			 */
			if (strcasecmp((char *)vp, "DMARC1") != 0)
			{
				return DMARC_PARSE_ERROR_BAD_VERSION;
			}
		}
		else if (strcasecmp((char *)cp, "p") == 0)
		{
			/*
			 * Be generous. Accept, for example, "p=r, p=rej, or any
			 * left match of "reject".
			 */
			if (strncasecmp((char *)vp, "reject", strlen((char *)vp)) == 0)
				pctx->p = DMARC_RECORD_P_REJECT;
			else if (strncasecmp((char *)vp, "none", strlen((char *)vp)) == 0)
				pctx->p = DMARC_RECORD_P_NONE;
			else if (strncasecmp((char *)vp, "quarantine", strlen((char *)vp)) == 0)
				pctx->p = DMARC_RECORD_P_QUARANTINE;
			else
			{
				/* A totaly unknown value */
				return DMARC_PARSE_ERROR_BAD_VALUE;
			}
		}
		else if (strcasecmp((char *)cp, "sp") == 0)
		{
			/*
			 * Be generous. Accept, for example, "sp=r, p=rej, or any
			 * left match of "reject".
			 */
			if (strncasecmp((char *)vp, "reject", strlen((char *)vp)) == 0)
				pctx->sp = DMARC_RECORD_P_REJECT;
			else if (strncasecmp((char *)vp, "none", strlen((char *)vp)) == 0)
				pctx->sp = DMARC_RECORD_P_NONE;
			else if (strncasecmp((char *)vp, "quarantine", strlen((char *)vp)) == 0)
				pctx->sp = DMARC_RECORD_P_QUARANTINE;
			else
			{
				/* A totaly unknown value */
				return DMARC_PARSE_ERROR_BAD_VALUE;
			}
		}
		else if (strcasecmp((char *)cp, "adkim") == 0)
		{
			/*
			 * Be generous. Accept, for example, "adkim=s, adkim=strict or any
			 * left match of "strict".
			 */
			if (strncasecmp((char *)vp, "strict", strlen((char *)vp)) == 0)
				pctx->adkim = DMARC_RECORD_A_STRICT;
			else if (strncasecmp((char *)vp, "relaxed", strlen((char *)vp)) == 0)
				pctx->adkim = DMARC_RECORD_A_RELAXED;
			else
			{
				/* A totaly unknown value */
				return DMARC_PARSE_ERROR_BAD_VALUE;
			}
		}
		else if (strcasecmp((char *)cp, "aspf") == 0)
		{
			/*
			 * Be generous. Accept, for example, "aspf=s, aspf=strict or any
			 * left match of "strict".
			 */
			if (strncasecmp((char *)vp, "strict", strlen((char *)vp)) == 0)
				pctx->aspf = DMARC_RECORD_A_STRICT;
			else if (strncasecmp((char *)vp, "relaxed", strlen((char *)vp)) == 0)
				pctx->aspf = DMARC_RECORD_A_RELAXED;
			else
			{
				/* A totaly unknown value */
				return DMARC_PARSE_ERROR_BAD_VALUE;
			}
		}
		else if (strcasecmp((char *)cp, "pct") == 0)
		{
			errno = 0;
			pctx->pct = strtoul(vp, NULL, 10);
			if (pctx->pct < 0 || pctx->pct > 100)
			{
				return DMARC_PARSE_ERROR_BAD_VALUE;
			}
			if (errno == EINVAL || errno == ERANGE)
			{
				return DMARC_PARSE_ERROR_BAD_VALUE;
			}
		}
		else if (strcasecmp((char *)cp, "ri") == 0)
		{
			char *xp;

			for (xp = vp; *xp != '\0'; ++xp)
			{
				if (! isdigit((int)*xp))
					return DMARC_PARSE_ERROR_BAD_VALUE;
			}
			errno = 0;
			pctx->ri = strtoul(vp, NULL, 10);
			if (errno == EINVAL || errno == ERANGE)
			{
				return DMARC_PARSE_ERROR_BAD_VALUE;
			}
		}
		else if (strcasecmp((char *)cp, "rf") == 0)
		{
			char *xp, *yp;

			/*
			 * The list may be a comma delimilted list of choices.
			 */
			for (xp = vp; *xp != '\0'; )
			{
				u_char xbuf[32];

				yp = strchr(xp, ',');
				if (yp != NULL)
					*yp = '\0';

				xp = opendmarc_util_cleanup(xp, xbuf, sizeof xbuf);
				if (xp != NULL || strlen((char *)xp) > 0)
				{
					/*
					 * Be generous. Accept, for example, "rf=a, aspf=afrf or any
					 * left match of "afrf".
					 */
					if (strncasecmp((char *)xp, "afrf", strlen((char *)xp)) == 0)
						pctx->rf |= DMARC_RECORD_RF_AFRF;
					else if (strncasecmp((char *)xp, "iodef", strlen((char *)xp)) == 0)
						pctx->aspf |= DMARC_RECORD_RF_IODEF;
					else
					{
						/* A totaly unknown value */
						return DMARC_PARSE_ERROR_BAD_VALUE;
					}
				}
				if (yp != NULL)
					xp = yp+1;
				else
					break;
			}
		}
		else if (strcasecmp((char *)cp, "rua") == 0)
		{
			char *xp, *yp;

			/*
			 * A possibly comma delimited list of URI of where to send reports.
			 */
			for (xp = vp; *xp != '\0'; )
			{
				u_char	xbuf[256];

				yp = strchr(xp, ',');
				if (yp != NULL)
					*yp = '\0';

				xp = opendmarc_util_cleanup(xp, xbuf, sizeof xbuf);
				if (xp != NULL || strlen((char *)xp) > 0)
				{
					pctx->rua_list = opendmarc_util_pushargv(xp, pctx->rua_list,
										&(pctx->rua_cnt));
				}
				if (yp != NULL)
					xp = yp+1;
				else
					break;
			}
		}
		else if (strcasecmp((char *)cp, "ruf") == 0)
		{
			char *xp, *yp;

			/*
			 * A possibly comma delimited list of URI of where to send 
			 * MARF reports.
			 */
			for (xp = vp; *xp != '\0'; )
			{
				u_char	xbuf[256];

				yp = strchr(xp, ',');
				if (yp != NULL)
					*yp = '\0';

				xp = opendmarc_util_cleanup(xp, xbuf, sizeof xbuf);
				if (xp != NULL || strlen((char *)xp) > 0)
				{
					pctx->ruf_list = opendmarc_util_pushargv(xp, pctx->ruf_list,
										&(pctx->ruf_cnt));
				}
				if (yp != NULL)
					xp = yp+1;
				else
					break;
			}
		}
		else if (strcasecmp((char *)cp, "fo") == 0)
		{
			char *xp, *yp;

			/*
			 * A possibly colon delimited list of on character settings.
			 */
			for (xp = vp; *xp != '\0'; )
			{
				u_char xbuf[256];

				yp = strchr(xp, ':');
				if (yp != NULL)
					*yp = '\0';

				xp = opendmarc_util_cleanup(xp, xbuf, sizeof xbuf);
				if (xp != NULL || strlen((char *)xp) > 0)
				{
					switch ((int)*xp)
					{
						case '0':
							pctx->fo |= DMARC_RECORD_FO_0;
							break;
						case '1':
							pctx->fo |= DMARC_RECORD_FO_1;
							break;
						case 'd':
						case 'D':
							pctx->fo |= DMARC_RECORD_FO_D;
							break;
						case 's':
						case 'S':
							pctx->fo |= DMARC_RECORD_FO_S;
							break;
						default:
							return DMARC_PARSE_ERROR_BAD_VALUE;
					}
				}
				if (yp != NULL)
					xp = yp+1;
				else
					break;
			}
		}

		cp = sp;
	}

	if (pctx->p == DMARC_RECORD_P_UNSPECIFIED)
	{
		return DMARC_PARSE_ERROR_NO_REQUIRED_P;
	}
	/*
	 * Set defaults for unspecifed tokens.
	 */
	if (pctx->adkim == DMARC_RECORD_A_UNSPECIFIED)
		pctx->adkim = DMARC_RECORD_A_RELAXED;
	if (pctx->aspf == DMARC_RECORD_A_UNSPECIFIED)
		pctx->aspf = DMARC_RECORD_A_RELAXED;
	if (pctx->pct < 0)
		pctx->pct = 100;
	if (pctx->rf == DMARC_RECORD_RF_UNSPECIFIED)
		pctx->rf = DMARC_RECORD_RF_AFRF;
	if (pctx->ri == -1)
		pctx->ri = 86400;
	if (pctx->fo == DMARC_RECORD_FO_UNSPECIFIED)
		pctx->fo = DMARC_RECORD_FO_0;

	if (pctx->from_domain == NULL)
		pctx->from_domain = strdup(domain);
	return DMARC_PARSE_OKAY;
}

/**************************************************************************
** OPENDMARC_POLICY_STORE_DMARC -- The application looked up the dmarc record
**					and hands it to us here.
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_policy_store_dmarc(DMARC_POLICY_T *pctx, u_char *dmarc_record, u_char *domain, u_char *organizationaldomain)
{
	OPENDMARC_STATUS_T status;

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (dmarc_record == NULL)
		return DMARC_PARSE_ERROR_EMPTY;
	if (domain == NULL)
		return DMARC_PARSE_ERROR_NO_DOMAIN;

	status = opendmarc_policy_parse_dmarc(pctx, domain , dmarc_record);
	if (status != DMARC_PARSE_OKAY)
		return status;

	if (pctx->from_domain != NULL)
		(void) free(pctx->from_domain);
	pctx->from_domain = strdup(domain);
	if (organizationaldomain != NULL)
	{
		if (pctx->organizational_domain != NULL)
			(void) free(pctx->organizational_domain);
		pctx->organizational_domain = (u_char *)strdup(organizationaldomain);
	}
	return DMARC_PARSE_OKAY;
}


/**************************************************************************
** DMARC LOOKUP HOOKS
***************************************************************************/

OPENDMARC_STATUS_T
opendmarc_policy_fetch_pct(DMARC_POLICY_T *pctx, int *pctp)
{
	if (pctx == NULL)
	{
		return DMARC_PARSE_ERROR_NULL_CTX;
	}
	if (pctp == NULL)
	{
		return DMARC_PARSE_ERROR_EMPTY;
	}
	*pctp = pctx->pct;
	return DMARC_PARSE_OKAY;
}

OPENDMARC_STATUS_T
opendmarc_policy_fetch_adkim(DMARC_POLICY_T *pctx, int *adkim)
{
	if (pctx == NULL)
	{
		return DMARC_PARSE_ERROR_NULL_CTX;
	}
	if (adkim == NULL)
	{
		return DMARC_PARSE_ERROR_EMPTY;
	}
	*adkim = pctx->adkim;
	return DMARC_PARSE_OKAY;
}

OPENDMARC_STATUS_T
opendmarc_policy_fetch_aspf(DMARC_POLICY_T *pctx, int *aspf)
{
	if (pctx == NULL)
	{
		return DMARC_PARSE_ERROR_NULL_CTX;
	}
	if (aspf == NULL)
	{
		return DMARC_PARSE_ERROR_EMPTY;
	}
	*aspf = pctx->aspf;
	return DMARC_PARSE_OKAY;
}

OPENDMARC_STATUS_T
opendmarc_policy_fetch_p(DMARC_POLICY_T *pctx, int *p)
{
	if (pctx == NULL)
	{
		return DMARC_PARSE_ERROR_NULL_CTX;
	}
	if (p == NULL)
	{
		return DMARC_PARSE_ERROR_EMPTY;
	}
	*p = pctx->p;
	return DMARC_PARSE_OKAY;
}

OPENDMARC_STATUS_T
opendmarc_policy_fetch_sp(DMARC_POLICY_T *pctx, int *sp)
{
	if (pctx == NULL)
	{
		return DMARC_PARSE_ERROR_NULL_CTX;
	}
	if (sp == NULL)
	{
		return DMARC_PARSE_ERROR_EMPTY;
	}
	*sp = pctx->sp;
	return DMARC_PARSE_OKAY;
}

u_char **
opendmarc_policy_fetch_rua(DMARC_POLICY_T *pctx, u_char *list_buf, size_t size_of_buf, int constant)
{
	u_char *sp, *ep, *rp;
	int	i;
	int	ret;

	if (pctx == NULL)
	{
		return NULL;
	}
	if (list_buf != NULL && size_of_buf > 0)
	{
		(void) memset(list_buf, '\0', size_of_buf);
		sp = list_buf;
		ep = list_buf + size_of_buf;
		for (i = 0; i < pctx->rua_cnt; i++)
		{
			ret = opendmarc_policy_query_dmarc_xdomain(pctx, pctx->rua_list[i]);
			if (ret != DMARC_PARSE_OKAY)
				continue;
			for (rp = (pctx->rua_list)[i]; *rp != '\0'; ++rp)
			{
				*sp++ = *rp;
				if (sp >= (ep - 2))
					break;
			}
			if (sp >= (ep - 2))
				break;
			if (i != (pctx->rua_cnt -1))
				*sp++ = ',';
			if (sp >= (ep - 2))
				break;
		}
	}
	if (constant != 0)
		return pctx->rua_list;
	return opendmarc_util_dupe_argv(pctx->rua_list);
}

OPENDMARC_STATUS_T
opendmarc_policy_fetch_alignment(DMARC_POLICY_T *pctx, int *dkim_alignment, int *spf_alignment)
{
	if (pctx == NULL)
	{
		return DMARC_PARSE_ERROR_NULL_CTX;
	}
	if (dkim_alignment != NULL)
	{
		*dkim_alignment = pctx->dkim_alignment;
	}
	if (spf_alignment != NULL)
	{
		*spf_alignment = pctx->spf_alignment;
	}
	return DMARC_PARSE_OKAY;
}

u_char **
opendmarc_policy_fetch_ruf(DMARC_POLICY_T *pctx, u_char *list_buf, size_t size_of_buf, int constant)
{
	u_char *sp, *ep, *rp;
	int	i;
	int	ret;

	if (pctx == NULL)
	{
		return NULL;
	}
	if (list_buf != NULL || size_of_buf > 0)
	{
		(void) memset(list_buf, '\0', size_of_buf);
		sp = list_buf;
		ep = list_buf + size_of_buf;
		for (i = 0; i < pctx->ruf_cnt; i++)
		{
			ret = opendmarc_policy_query_dmarc_xdomain(pctx, pctx->ruf_list[i]);
			if (ret != DMARC_PARSE_OKAY)
				continue;
			for (rp = (pctx->ruf_list)[i]; *rp != '\0'; ++rp)
			{
				*sp++ = *rp;
				if (sp >= (ep - 2))
					break;
			}
			if (sp >= (ep - 2))
				break;
			if (i != (pctx->ruf_cnt -1))
				*sp++ = ',';
			if (sp >= (ep - 2))
				break;
		}
	}
	if (constant != 0)
		return pctx->ruf_list;
	return opendmarc_util_dupe_argv(pctx->ruf_list);
}

OPENDMARC_STATUS_T
opendmarc_policy_fetch_fo(DMARC_POLICY_T *pctx, int *fo)
{
	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (fo == NULL)
		return DMARC_PARSE_ERROR_EMPTY;
	if (pctx->ruf_list == NULL)
		*fo = DMARC_RECORD_FO_UNSPECIFIED;
	else
		*fo = pctx->fo;
	return DMARC_PARSE_OKAY;
}

OPENDMARC_STATUS_T
opendmarc_policy_fetch_rf(DMARC_POLICY_T *pctx, int *rf)
{
	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (rf == NULL)
		return DMARC_PARSE_ERROR_EMPTY;
	if (pctx->ruf_list == NULL)
		*rf = DMARC_RECORD_RF_UNSPECIFIED;
	else
		*rf = pctx->rf;
	return DMARC_PARSE_OKAY;
}

/**************************************************************************************************
** OPENDMARC_POLICY_FETCH_UTILIZED_DOMAIN -- Return domain used to get the dmarc record
**					     Either the From: domain or the organizational domain
**	Arguments
**		pctx	-- Address of a policy context
**		buf	-- Where to scribble result
**		buflen	-- Size of buffer
**	Returns
**		DMARC_PARSE_OKAY		-- On success
**		DMARC_PARSE_ERROR_NULL_CTX	-- If context NULL
**		DMARC_PARSE_ERROR_EMPTY 	-- If buf null or buflen 0 sized
**		DMARC_PARSE_ERROR_NO_DOMAIN 	-- If neigher address is available
**/
OPENDMARC_STATUS_T
opendmarc_policy_fetch_utilized_domain(DMARC_POLICY_T *pctx, u_char *buf, size_t buflen)
{
	u_char *which = NULL;

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (buf == NULL || buflen == 0)
		return DMARC_PARSE_ERROR_EMPTY;

	if (pctx->organizational_domain != NULL)
		which = pctx->organizational_domain;
	else if (pctx->from_domain != NULL)
		which = pctx->from_domain;
	if (which == NULL)
		return DMARC_PARSE_ERROR_NO_DOMAIN;
# if HAVE_STRLCPY
	(void) strlcpy((char *)buf, (char *)which, buflen);
# else
	(void) strncpy((char *)buf, (char *)which, buflen);
# endif
	return DMARC_PARSE_OKAY;
}

/**************************************************************************
** OPENDMARC_GET_POLICY_TOKEN_USED -- Which policy was actually used
**
**	Parameters:
**		pctx	-- A Policy context
**	Returns:
**		DMARC_PARSE_ERROR_NULL_CTX	-- pctx == NULL
**		DMARC_USED_POLICY_IS_P		-- Domain policy is used
**		DMARC_USED_POLICY_IS_SP		-- Sub-domain policy is used
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_get_policy_token_used(DMARC_POLICY_T *pctx)
{

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (pctx->organizational_domain != NULL &&
	    pctx->sp != DMARC_RECORD_P_UNSPECIFIED)
		return DMARC_USED_POLICY_IS_SP;
	else
		return DMARC_USED_POLICY_IS_P;
}

/******************************************************************************
** OPENDMARC_POLICY_LIBRARY_DNS_HOOK -- Internal hook for dmarc_dns_get_record
*******************************************************************************/
void
opendmarc_policy_library_dns_hook(int *nscountp,
                                  struct sockaddr_in *nsaddr_list)
{
	int i;

	if (nscountp == NULL || nsaddr_list == NULL)
		return;
	if (Opendmarc_Libp == NULL)
		return;
	if (Opendmarc_Libp->nscount == 0 || Opendmarc_Libp->nscount >= MAXNS)
		return;
	for (i = 0; i < Opendmarc_Libp->nscount; i++)
	{
		nsaddr_list[i] = Opendmarc_Libp->nsaddr_list[i];
	}
	*nscountp = i;
	return;
}

/**************************************************************************
** OPENDMARC_POLICY_STATUS_TO_STR -- Convert the integer return
**				     of type OPENDMARC_STATUS_T into 
**				     a human readable string.
**	Parameters:
**		status	-- The status for which to return a string
**	Returns:
**		NULL		-- On error
**		const char *	-- On success
***************************************************************************/
const char *
opendmarc_policy_status_to_str(OPENDMARC_STATUS_T status)
{
	char *msg = "Undefine Value";

	switch (status)
	{
	    case DMARC_PARSE_OKAY:
	    	msg = "Success. No Errors";
		break;
	    case DMARC_PARSE_ERROR_EMPTY: 
		msg = "Function called with nothing to parse";
		break;
	    case DMARC_PARSE_ERROR_NULL_CTX: 
		msg  ="Function called with NULL Context";
		break;
	    case DMARC_PARSE_ERROR_BAD_VERSION: 
		msg = "Found DMARC record containd a bad v= value";
		break;
	    case DMARC_PARSE_ERROR_BAD_VALUE: 
		msg = "Found DMARC record containd a bad token value";
		break;
	    case DMARC_PARSE_ERROR_NO_REQUIRED_P: 
		msg = "Found DMARC record lacked a required p= entry";
		break;
	    case DMARC_PARSE_ERROR_NO_DOMAIN: 
		msg = "Function found the domain empty, e.g. \"<>\"";
		break;
	    case DMARC_PARSE_ERROR_NO_ALLOC: 
		msg = "Memory allocation error";
		break;
	    case DMARC_PARSE_ERROR_BAD_SPF_MACRO: 
		msg = "Attempt to store an illegal value";
		break;
	    case DMARC_DNS_ERROR_NO_RECORD: 
		msg = "Looked up domain lacked a DMARC record";
		break;
	    case DMARC_DNS_ERROR_NXDOMAIN: 
		msg = "Looked up domain did not exist";
		break;
	    case DMARC_DNS_ERROR_TMPERR: 
		msg = "DNS lookup of domain tempfailed";
		break;
	    case DMARC_TLD_ERROR_UNKNOWN: 
		msg = "Attempt to load an unknown TLD file type";
		break;
	    case DMARC_FROM_DOMAIN_ABSENT: 
		msg = "No From: domain was supplied";
		break;
	    case DMARC_POLICY_ABSENT: 
		msg = "Policy up to you. No DMARC record found";
		break;
	    case DMARC_POLICY_PASS: 
		msg = "Policy OK so accept message";
		break;
	    case DMARC_POLICY_REJECT: 
		msg = "Policy says to reject message";
		break;
	    case DMARC_POLICY_QUARANTINE: 
		msg = "Policy says to quarantine message";
		break;
	    case DMARC_POLICY_NONE: 
		msg = "Policy says to monitor and report";
		break;
	}
	return msg;
}

/*******************************************************************************
** OPENDMARC_POLICY_TO_BUF -- Dump the DMARC_POLICY_T to a user supplied buffer
**	Arguments:
**		pctx		A pointer to a filled in DMARC_POLICY_T sttucture
**		buf		A char * buffer
**		buflen		The size of the char * buffer
**	Returns:
**		0 		On success
**		>0 		On failure, and fills errno with the error
**	Side Effects:
**		Blindly overwrites buffer.
*******************************************************************************/
int
opendmarc_policy_to_buf(DMARC_POLICY_T *pctx, char *buf, size_t buflen)
{
	char	nbuf[32];
	int	i;

	if (pctx == NULL || buf == NULL || buflen == 0)
		return errno = EINVAL;

	(void) memset(buf, '\0', buflen);

	if (strlcat(buf, "IP_ADDR=", buflen) >= buflen) return E2BIG;
	if (pctx->ip_addr != NULL)
		if (strlcat(buf, pctx->ip_addr, buflen) >= buflen) return E2BIG;
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "IP_TYPE=", buflen) >= buflen) return E2BIG;
	if (pctx->ip_addr != NULL)
	{
		if (pctx->ip_type == DMARC_POLICY_IP_TYPE_IPV4)
		{
			if (strlcat(buf, "IPv4", buflen) >= buflen) return E2BIG;
		}
		else if (pctx->ip_type == DMARC_POLICY_IP_TYPE_IPV6)
		{
			if (strlcat(buf, "IPv6", buflen) >= buflen) return E2BIG;
		}
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "SPF_DOMAIN=", buflen) >= buflen) return E2BIG;
	if (pctx->spf_domain != NULL)
		if (strlcat(buf, pctx->spf_domain, buflen) >= buflen) return E2BIG;
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "SPF_ORIGIN=", buflen) >= buflen) return E2BIG;
	if (pctx->spf_origin != 0)
	{
		if (pctx->spf_origin == DMARC_POLICY_SPF_ORIGIN_MAILFROM)
		{
			if (strlcat(buf, "MAILFROM", buflen) >= buflen) return E2BIG;
		}
		else if (pctx->spf_origin == DMARC_POLICY_SPF_ORIGIN_HELO)
		{
			if (strlcat(buf, "HELO", buflen) >= buflen) return E2BIG;
		}
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "SPF_OUTCOME=", buflen) >= buflen) return E2BIG;
	switch (pctx->spf_outcome)
	{
		default:
		case DMARC_POLICY_DKIM_OUTCOME_NONE:
			if (strlcat(buf, "NONE", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_POLICY_DKIM_OUTCOME_PASS:
			if (strlcat(buf, "PASS", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_POLICY_DKIM_OUTCOME_FAIL:
			if (strlcat(buf, "FAIL", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_POLICY_DKIM_OUTCOME_TMPFAIL:
			if (strlcat(buf, "TMPFAIL", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "SPF_HUMAN_OUTCOME=", buflen) >= buflen) return E2BIG;
	if (pctx->spf_human_outcome != NULL)
		if (strlcat(buf, pctx->spf_human_outcome, buflen) >= buflen) return E2BIG;
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "DKIM_FINAL=", buflen) >= buflen) return E2BIG;
	switch (pctx->dkim_final)
	{
		case TRUE:
			if (strlcat(buf, "TRUE", buflen) >= buflen) return E2BIG;
			break;
		default:
		case FALSE:
			if (strlcat(buf, "FALSE", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "DKIM_DOMAIN=", buflen) >= buflen) return E2BIG;
	if (pctx->dkim_domain != NULL)
		if (strlcat(buf, pctx->dkim_domain, buflen) >= buflen) return E2BIG;
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "DKIM_OUTOME=", buflen) >= buflen) return E2BIG;
	switch (pctx->dkim_outcome)
	{
		default:
		case DMARC_POLICY_DKIM_OUTCOME_NONE:
			if (strlcat(buf, "NONE", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_POLICY_DKIM_OUTCOME_PASS:
			if (strlcat(buf, "PASS", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_POLICY_DKIM_OUTCOME_FAIL:
			if (strlcat(buf, "FAIL", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_POLICY_DKIM_OUTCOME_TMPFAIL:
			if (strlcat(buf, "TMPFAIL", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "DKIM_HUMAN_OUTCOME=", buflen) >= buflen) return E2BIG;
	if (pctx->dkim_human_outcome != NULL)
		if (strlcat(buf, pctx->dkim_human_outcome, buflen) >= buflen) return E2BIG;
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "DKIM_ALIGNMENT=", buflen) >= buflen) return E2BIG;
	switch (pctx->dkim_alignment)
	{
		case DMARC_POLICY_DKIM_ALIGNMENT_PASS:
			if (strlcat(buf, "PASS", buflen) >= buflen) return E2BIG;
			break;
		default:
		case DMARC_POLICY_DKIM_ALIGNMENT_FAIL:
			if (strlcat(buf, "FAIL", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "SPF_ALIGNMENT=", buflen) >= buflen) return E2BIG;
	switch (pctx->spf_alignment)
	{
		case DMARC_POLICY_SPF_ALIGNMENT_PASS:
			if (strlcat(buf, "PASS", buflen) >= buflen) return E2BIG;
			break;
		default:
		case DMARC_POLICY_SPF_ALIGNMENT_FAIL:
			if (strlcat(buf, "FAIL", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "H_ERRNO=", buflen) >= buflen) return E2BIG;
	switch (pctx->h_error)
	{
		case HOST_NOT_FOUND:
			if (strlcat(buf, "HOST_NOT_FOUND", buflen) >= buflen) return E2BIG;
			break;
		case TRY_AGAIN:
			if (strlcat(buf, "TRY_AGAIN", buflen) >= buflen) return E2BIG;
			break;
		case NO_RECOVERY:
			if (strlcat(buf, "NO_RECOVERY", buflen) >= buflen) return E2BIG;
			break;
		case NO_DATA:
			if (strlcat(buf, "NO_DATA", buflen) >= buflen) return E2BIG;
			break;
		case NETDB_INTERNAL:
			if (strlcat(buf, "NETDB_INTERNAL", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "ADKIM=", buflen) >= buflen) return E2BIG;
	switch (pctx->adkim)
	{
		case DMARC_RECORD_A_UNSPECIFIED:
			if (strlcat(buf, "UNSPECIFIED", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_A_STRICT:
			if (strlcat(buf, "STRICT", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_A_RELAXED:
			if (strlcat(buf, "RELAXED", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "ASPF=", buflen) >= buflen) return E2BIG;
	switch (pctx->aspf)
	{
		case DMARC_RECORD_A_UNSPECIFIED:
			if (strlcat(buf, "UNSPECIFIED", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_A_STRICT:
			if (strlcat(buf, "STRICT", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_A_RELAXED:
			if (strlcat(buf, "RELAXED", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "P=", buflen) >= buflen) return E2BIG;
	switch (pctx->p)
	{
		case DMARC_RECORD_A_UNSPECIFIED:
			if (strlcat(buf, "UNSPECIFIED", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_P_NONE:
			if (strlcat(buf, "NONE", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_P_QUARANTINE:
			if (strlcat(buf, "QUARANTINE", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_P_REJECT:
			if (strlcat(buf, "REJECT", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "SP=", buflen) >= buflen) return E2BIG;
	switch (pctx->sp)
	{
		case DMARC_RECORD_A_UNSPECIFIED:
			if (strlcat(buf, "UNSPECIFIED", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_P_NONE:
			if (strlcat(buf, "NONE", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_P_QUARANTINE:
			if (strlcat(buf, "QUARANTINE", buflen) >= buflen) return E2BIG;
			break;
		case DMARC_RECORD_P_REJECT:
			if (strlcat(buf, "REJECT", buflen) >= buflen) return E2BIG;
			break;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "PCT=", buflen) >= buflen) return E2BIG;
	(void) snprintf(nbuf, sizeof nbuf, "%d", pctx->pct);
	if (strlcat(buf, nbuf, buflen) >= buflen) return E2BIG;
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "RF=", buflen) >= buflen) return E2BIG;
	if (pctx->rf == 0)
	{
		if (strlcat(buf, "UNSPECIFIED", buflen) >= buflen) return E2BIG;
	}
	if ((pctx->rf&DMARC_RECORD_RF_AFRF) != 0)
	{
		if (strlcat(buf, "AFRF", buflen) >= buflen) return E2BIG;
	}
	if ((pctx->rf&DMARC_RECORD_RF_IODEF) != 0 &&
	    (pctx->rf&DMARC_RECORD_RF_AFRF) != 0)
	{
		if (strlcat(buf, ",", buflen) >= buflen) return E2BIG;
	}
	if ((pctx->rf&DMARC_RECORD_RF_IODEF) != 0)
	{
		if (strlcat(buf, "IODEF", buflen) >= buflen) return E2BIG;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "RI=", buflen) >= buflen) return E2BIG;
	(void) snprintf(nbuf, sizeof nbuf, "%d", pctx->ri);
	if (strlcat(buf, nbuf, buflen) >= buflen) return E2BIG;
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "RUA=", buflen) >= buflen) return E2BIG;
	for (i = 0; i < pctx->rua_cnt; ++i)
	{
		if (i > 0)
		{
			if (strlcat(buf, ",", buflen) >= buflen) return E2BIG;
		}
		if (strlcat(buf, (pctx->rua_list)[i], buflen) >= buflen) return E2BIG;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "RUF=", buflen) >= buflen) return E2BIG;
	for (i = 0; i < pctx->ruf_cnt; ++i)
	{
		if (i > 0)
		{
			if (strlcat(buf, ",", buflen) >= buflen) return E2BIG;
		}
		if (strlcat(buf, (pctx->ruf_list)[i], buflen) >= buflen) return E2BIG;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	if (strlcat(buf, "FO=", buflen) >= buflen) return E2BIG;
	if (pctx->ruf_list == NULL || pctx->fo == DMARC_RECORD_FO_UNSPECIFIED)
	{
		if (strlcat(buf, "UNSPECIFIED", buflen) >= buflen) return E2BIG;
	}
	if ((pctx->fo&DMARC_RECORD_FO_0) != 0)
	{
		if (strlcat(buf, "0:", buflen) >= buflen) return E2BIG;
	}
	if ((pctx->fo&DMARC_RECORD_FO_1) != 0)
	{
		if (strlcat(buf, "1:", buflen) >= buflen) return E2BIG;
	}
	if ((pctx->fo&DMARC_RECORD_FO_D) != 0)
	{
		if (strlcat(buf, "d:", buflen) >= buflen) return E2BIG;
	}
	if ((pctx->fo&DMARC_RECORD_FO_S) != 0)
	{
		if (strlcat(buf, "s:", buflen) >= buflen) return E2BIG;
	}
	if (strlcat(buf, "\n", buflen) >= buflen) return E2BIG;

	return 0;
}
