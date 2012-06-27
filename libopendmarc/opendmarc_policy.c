/*************************************************************************
** $Id: opendmarc_policy.c,v 1.2 2010/12/03 23:06:48 bcx Exp $
** The user interface to the rest of this library.
**
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
**************************************************************************/
#include "opendmarc_internal.h"
#define OPENDMARC_POLICY_C
#include "dmarc.h"

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

	(void) memset(pctx, '\0', sizeof(DMARC_POLICY_T));
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
opendmarc_policy_store_spf(DMARC_POLICY_T *pctx, u_char *domain, int result, int origin, u_char *human_result)
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
	if (human_result != NULL)
		pctx->spf_human_outcome = strdup((char *)human_result);
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
		default:
			return DMARC_PARSE_ERROR_BAD_SPF_MACRO;
	}
	switch (origin)
	{
		case DMARC_POLICY_SPF_ORIGIN_MAILFROM:
		case DMARC_POLICY_SPF_ORIGIN_HELO:
			pctx->spf_origin = origin;
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
		default:
			return DMARC_PARSE_ERROR_BAD_DKIM_MACRO;
	}

	dp = opendmarc_util_finddomain(d_equal_domain, domain_buf, sizeof domain_buf);
	if (dp == NULL)
		return DMARC_PARSE_ERROR_NO_DOMAIN;

	if (pctx->dkim_outcome != DMARC_POLICY_DKIM_OUTCOME_PASS)
	{
		if (pctx->dkim_domain != NULL)
		{
			(void) free(pctx->dkim_domain);
			pctx->dkim_domain = NULL;
		}
	}
	if (pctx->dkim_domain == NULL)
	{
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
	}
	return DMARC_PARSE_OKAY;
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
	int		reply = 0;

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;
	if (domain == NULL || strlen(domain) == 0)
		return DMARC_PARSE_ERROR_EMPTY;

	(void) memset(copy, '\0', sizeof copy);
	(void) snprintf(copy, sizeof copy, "_dmarc.%s", domain);

	bp = dmarc_dns_get_record(copy, &reply, buf, sizeof buf);
	if (bp == NULL || reply != 0)
	{
		(void) memset(tld, '\0', sizeof tld);
		reply = opendmarc_get_tld(domain, tld, sizeof tld);
		if (reply == 0 && strlen(tld) > 0 && strcasecmp(domain, tld) != 0)
		{
			(void) snprintf(copy, sizeof copy, "_dmarc.%s", tld);
			bp = dmarc_dns_get_record(copy, &reply, buf, sizeof buf);
			if (bp == NULL || reply != 0)
			switch (reply)
			{
				case HOST_NOT_FOUND:
					return DMARC_DNS_ERROR_NXDOMAIN;
				case NO_DATA:
				case NO_RECOVERY:
					return DMARC_DNS_ERROR_NO_RECORD;
				case TRY_AGAIN:
					return DMARC_DNS_ERROR_TMPERR;
				default:
					return reply;

			}
			pctx->organizational_domain = strdup(tld);
		}
	}
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
**		DMARC_POLICY_NONE		-- Accept and report
**		DMARC_POLICY_REJECT		-- Policy says to reject the message
**		DMARC_POLICY_QUARANTINE		-- Policy says to quaranteen the message
**		DMARC_POLICY_PASS		-- Policy says to accept the message
**	Side Effects:
**		Checks for domain alignment.
***************************************************************************/
OPENDMARC_STATUS_T
opendmarc_get_policy_to_enforce(DMARC_POLICY_T *pctx)
{
	u_char	rev_from_domain[MAXDNSHOSTNAME];
	u_char	rev_spf_domain[MAXDNSHOSTNAME];
	u_char	rev_dkim_domain[MAXDNSHOSTNAME];

	if (pctx == NULL)
		return DMARC_PARSE_ERROR_NULL_CTX;

	if (pctx->from_domain == NULL)
		return DMARC_POLICY_ABSENT;

	if (pctx->from_domain == NULL)
		return DMARC_FROM_DOMAIN_ABSENT;
	(void) opendmarc_reverse_domain(pctx->from_domain, rev_from_domain, sizeof rev_from_domain);

	/*
	 * If dkim passes and dkim aligns OR spf passes and spf aligns
	 * Accept the message.
	 */
	if (pctx->dkim_domain != NULL && pctx->dkim_outcome == DMARC_POLICY_DKIM_OUTCOME_PASS)
	{
		
		(void) opendmarc_reverse_domain(pctx->dkim_domain, rev_dkim_domain, sizeof rev_dkim_domain);
		if (pctx->adkim == DMARC_RECORD_A_STRICT)
		{
			if (strcasecmp((char *)rev_from_domain, (char *)rev_dkim_domain) == 0)
				return DMARC_POLICY_PASS;
		}
		else
		{
			if (strncasecmp((char *)rev_from_domain, (char *)rev_dkim_domain, strlen((char *)rev_dkim_domain)) == 0)
				return DMARC_POLICY_PASS;
		}
	}

	if (pctx->spf_domain != NULL && pctx->spf_outcome == DMARC_POLICY_SPF_OUTCOME_PASS)
	{
		
		(void) opendmarc_reverse_domain(pctx->spf_domain, rev_spf_domain, sizeof rev_spf_domain);
		if (pctx->aspf == DMARC_RECORD_A_STRICT)
		{
			if (strcasecmp((char *)rev_from_domain, (char *)rev_spf_domain) == 0)
				return DMARC_POLICY_PASS;
		}
		else
		{
			if (strncasecmp((char *)rev_from_domain, (char *)rev_spf_domain, strlen((char *)rev_spf_domain)) == 0)
				return DMARC_POLICY_PASS;
		}
	}

	switch (pctx->p)
	{
		case DMARC_RECORD_P_REJECT:
			return DMARC_POLICY_REJECT;
		case DMARC_RECORD_P_QUARANTINE:
			return DMARC_POLICY_QUARANTINE;
		case DMARC_RECORD_P_UNSPECIFIED:
		case DMARC_RECORD_P_NONE:
		default:
			break;
	}
	return DMARC_POLICY_PASS;
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
	pctx->p   = DMARC_RECORD_P_UNSPECIFIED;
	pctx->pct = -1;
	pctx->ri  = -1;

	(void) memset((char *)copy, '\0', sizeof copy);
# if HAVE_STRLCPY
	(void) strlcpy((char *)copy, (char *)record, sizeof copy);
# else
	(void) strncpy((char *)copy, (char *)record, sizeof copy);
# endif
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

			for (xp = cp; *xp != '\0'; ++xp)
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
				u_char xbuf[256];

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
				u_char xbuf[256];

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

u_char **
opendmarc_policy_fetch_ruf(DMARC_POLICY_T *pctx, u_char *list_buf, size_t size_of_buf, int constant)
{
	u_char *sp, *ep, *rp;
	int	i;

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

/**************************************************************************************************
** OPENDMARC_POLICY_FETCH_UTILIZED_DOMAIN -- Return domain used to get the dmarc record
**					     Either the From: domain or the organizational domain
**	Arguments
**		pctx	-- Address of a policy context
**		bud	-- Where to scribble result
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
	if (pctx->from_domain != NULL)
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

/******************************************************************************
** OPENDMARC_POLICY_LIBRARY_DNS_HOOK -- Internal hook for dmarc_dns_get_record
*******************************************************************************/
void
opendmarc_policy_library_dns_hook(int *nscountp, struct sockaddr_in *(nsaddr_list[]))
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
		(void) memcpy(&(Opendmarc_Libp->nsaddr_list)[i], &(*nsaddr_list)[i], sizeof(struct sockaddr_in));
	}
	*nscountp = i;
	return;
}

