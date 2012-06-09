/*************************************************************************
** $Id: opendmarc_policy.c,v 1.2 2010/12/03 23:06:48 bcx Exp $
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
**************************************************************************/
#include "opendmarc_internal.h"
#define OPENDMARC_POLICY_C
#include "dmarc.h"

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_INIT -- Get policy context for connection
***************************************************************************/
DMARC_POLICY_T *
opendmarc_policy_connect_init(u_char *ip_addr, int ip_type)
{
	DMARC_POLICY_T *pctx;
	int		xerrno;

	if (ip_addr == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	if (ip_type != DMARC_POLICY_IP_TYPE_IPV4 && ip_type != DMARC_POLICY_IP_TYPE_IPV6)
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
	pctx->ip_type = ip_type;
	return pctx;
}

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_CLEAR -- Zero the policy context
***************************************************************************/
DMARC_POLICY_T *
opendmarc_policy_connect_clear(DMARC_POLICY_T *pctx)
{
	if (pctx == NULL)
		return NULL;

	if (pctx->ip_addr != NULL)
		(void) free(pctx->ip_addr);
	if (pctx->domain != NULL)
		(void) free(pctx->domain);
	if (pctx->spf_human_outcome != NULL)
		(void) free(pctx->spf_human_outcome);
	if (pctx->dkim_human_outcome != NULL)
		(void) free(pctx->dkim_human_outcome);
	if (pctx->organizational_domain != NULL)
		(void) free(pctx->organizational_domain);
	pctx->rua_list = opendmarc_util_clearargv(pctx->rua_list);
	pctx->ruf_list = opendmarc_util_clearargv(pctx->ruf_list);

	(void) memset(pctx, '\0', sizeof(DMARC_POLICY_T));
	return pctx;
}

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_RSET -- Rset for another message
***************************************************************************/
DMARC_POLICY_T *
opendmarc_policy_connect_rset(DMARC_POLICY_T *pctx)
{
	u_char *ip_save;
	int     ip_type;

	if (pctx == NULL)
		return NULL;

	ip_save       = pctx->ip_addr;
	pctx->ip_addr = NULL;
	ip_type       = pctx->ip_type;
	pctx->ip_type = NULL;

	pctx = opendmarc_policy_connect_clear(pctx);

	if (pctx == NULL)
		return NULL;
	pctx->ip_addr = ip_save;
	pctx->ip_type = ip_type;
	return pctx;
}

/**************************************************************************
** OPENDMARC_POLICY_CONNECT_SHUTDOWN -- Free the policy context
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
** OPENDMARC_POLICY_FROM_DOMAIN -- Store domain from the From: header.
**
** If the domain is an address parse the domain from it.
***************************************************************************/
int
opendmarc_policy_from_domain(DMARC_POLICY_T *pctx, u_char *from_domain)
{
	return 0;
}

/**************************************************************************
** OPENDMARC_POLICY_STORE_SPF -- Store spf results
***************************************************************************/
int
opendmarc_policy_store_spf(DMARC_POLICY_T *pctx, u_char *domain, u_char *result, u_char *origin, u_char *human_result)
{
	return 0;
}

/**************************************************************************
** OPENDMARC_POLICY_STORE_DKIM -- Store dkim results
***************************************************************************/
int
opendmarc_policy_store_dkim(DMARC_POLICY_T *pctx, u_char *domain, u_char *result, u_char *human_result)
{
	return 0;
}

/**************************************************************************
** OPENDMARC_POLICY_STORE_DMARC -- The application looked up the dmarc record
**					and hands it to us here.
***************************************************************************/
int
opendmarc_policy_store_dmarc(DMARC_POLICY_T *pctx, u_char *dmarc_record, u_char *organizationaldomain)
{
	return 0;
}

/**************************************************************************
** OPENDMARC_POLICY_QUERY_DMARC -- Look up the _dmarc record for the 
**					specified domain. If not found
**				  	try the organizational domain.
***************************************************************************/
int
opendmarc_policy_query_dmarc(DMARC_POLICY_T *pctx, u_char *domain)
{
	return 0;
}

/**************************************************************************
** OPENDMARC_GET_POLICY_TO_ENFORCE -- What to do with this message. i.e. allow
**				possible delivery, quarantine, or reject.
***************************************************************************/
int
opendmarc_get_policy_to_enforce(DMARC_POLICY_T *pctx)
{
	return 0;
}

/*****************************************************
**  OPENDMARC_PARSE_DMARC -- Parse a DMARC record
**
**	Parameters:
**		pctx	-- A Policy context
**		record	-- The DMARC record to parse
**		err	-- The error if any.
**	Returns:
**		pctx always
**		sets *err to non-zero on error (see libopendmarc.h)
**	Side Effects:
**		Allocates memory.
*/

DMARC_POLICY_T *
opendmarc_parse_dmarc(DMARC_POLICY_T *pctx, u_char *record, int *err)
{
	u_char *cp, *eqp, *ep, *sp, *vp;
	u_char copy[BUFSIZ];

	if (pctx == NULL || record == NULL)
	{
		if (*err != NULL)
			*err = DMARC_PARSE_ERROR_EMPTY;
		return pctx;
	}
	/*
	 * Set the defaults to detect missing required items.
	 */
	pctx->p = DMARC_RECORD_P_UNSPECIFIED;

	(void) memset((char *)copy, '\0', sizeof copy);
	(void) strlcpy((char *)copy, (char *)record, sizeof copy);
	ep = (u_char *)strlen((char *)copy);

	for (cp = copy; cp < ep; ++cp)
	{
		sp = (u_char *)strchr(cp, ';');
		if (sp != NULL)
			*sp = '\0';
		for (; cp != '\0'; ++cp)
		{
			if (! isascii((int)*eqp) && ! isspace((int)*cp))
				break;
		}
		eqp = (u_char *)strchr((char *)cp, '=');
		if (eqp == NULL)
		{
			cp = sp;
			continue;
		}
		*eqp = '\0';
		vp = eqp + 1;
		for (--eqp; eqp > cp; --eqp)
		{
			if (isascii((int)*eqp) && isspace((int)*eqp))
				*eqp = '\0';
			else
				break;
		}
		/*
		 * cp now points to the token name with all surronding
		 * whitepace removed.
		 */
		if (strlen((char *)cp) == 0)
		{
			cp = sp;
			continue;
		}
		for (; vp != '\0'; ++vp)
		{
			if (! isascii((int)*eqp) && ! isspace((int)*vp))
				break;
		}
		for (eqp = sp -1; eqp > vp; --eqp)
		{
			if (isascii((int)*eqp) && isspace((int)*eqp))
				*eqp = '\0';
			else
				break;
		}
		if (strlen((char *)vp) == 0)
		{
			cp = sp;
			continue;
		}
		/*
		 * vp now points to the token value with all surronding
		 * whitepace removed.
		 */
		if (strcasecmp((char *)cp, "v") == 0)
		{
			if (strcasecmp((char *)vp, "DMARC1") != 0)
			{
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VERSION;
				return pctx;
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
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VALUE;
				return pctx;
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
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VALUE;
				return pctx;
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
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VALUE;
				return pctx;
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
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VALUE;
				return pctx;
			}
		}
		else if (strcasecmp((char *)cp, "pct") == 0)
		{
			errno = 0;
			pctx->pct = strtoul(vp, NULL, 10);
			if (pctx->pct < 0 || pctx->pct > 100)
			{
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VALUE;
				return pctx;
			}
			if (errno == EINVAL || errno == ERANGE)
			{
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VALUE;
				return pctx;
			}
		}
		else if (strcasecmp((char *)cp, "ri") == 0)
		{
			errno = 0;
			pctx->ri = strtoul(vp, NULL, 10);
			if (errno == EINVAL || errno == ERANGE)
			{
				if (*err)
					*err = DMARC_PARSE_ERROR_BAD_VALUE;
				return pctx;
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
				yp = strchr(xp, ',');
				if (yp != NULL)
					*yp = '\0';

				/*
				 * Be generous. Accept, for example, "rf=a, aspf=afrf or any
				 * left match of "afrf".
				 */
				if (strncasecmp((char *)xp, "afrf", strlen((char *)xp)) == 0)
					pctx->rf |= DMARC_RECORD_R_AFRF;
				else if (strncasecmp((char *)xp, "iodef", strlen((char *)xp)) == 0)
					pctx->aspf |= DMARC_RECORD_R_IODEF;
				else
				{
					/* A totaly unknown value */
					if (*err)
						*err = DMARC_PARSE_ERROR_BAD_VALUE;
					return pctx;
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
		if (err != NULL)
			*err = DMARC_PARSE_ERROR_NO_REQUIRED_P;
		return pctx;
	}
	return pctx;
}
