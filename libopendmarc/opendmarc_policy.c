/*************************************************************************
** $Id: opendmarc_policy.c,v 1.2 2010/12/03 23:06:48 bcx Exp $
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
**************************************************************************/
#include "opendmarc_internal.h"
#define OPENDMARC_POLICY_C
#include "libopendmarc.h"

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
