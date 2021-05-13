/********************************************************************
** OPENDMARC_SPF.C --  Process the spf record of the inbound message
**********************************************************************/ 
# include "opendmarc_internal.h"

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

#include <stdarg.h>

# include "dmarc.h"

#if WITH_SPF

#if HAVE_SPF2_H
// Here we have spf.h, so libspf2 is available.

SPF_CTX_T *
opendmarc_spf2_alloc_ctx()
{
	SPF_CTX_T *spfctx = NULL;

	spfctx = malloc(sizeof(SPF_CTX_T));
	if (spfctx == NULL)
		return NULL;
	(void) memset(spfctx, '\0', sizeof(SPF_CTX_T));
	spfctx->spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
	spfctx->spf_request = SPF_request_new(spfctx->spf_server);
	return spfctx;
}

SPF_CTX_T *
opendmarc_spf2_free_ctx(SPF_CTX_T *spfctx)
{
	if (spfctx == NULL)
		return spfctx;

	if (spfctx->spf_response != NULL)
		SPF_response_free(spfctx->spf_response);
	if (spfctx->spf_request != NULL)
		SPF_request_free(spfctx->spf_request);
	if (spfctx->spf_server != NULL)
		SPF_server_free(spfctx->spf_server);
	(void) free(spfctx);
	spfctx = NULL;
	return spfctx;
}

int
opendmarc_spf2_find_mailfrom_domain(SPF_CTX_T *spfctx, char *raw_address, char *mailfrom, size_t mailfrom_len, int *use_flag)
{
	char copy[sizeof spfctx->mailfrom_addr];
	char *cp;
	char *ep;

	if (use_flag != NULL)
		*use_flag = FALSE;

	if (spfctx == NULL)
		return EINVAL;

	if (mailfrom == NULL || raw_address == NULL)
		return EINVAL;
	
	(void) memset(copy, '\0', sizeof copy);
	(void) strlcpy(copy, raw_address, sizeof copy);

	cp = strrchr(copy, '<');
	if (cp == NULL)
		cp = copy;
	else
		++cp;
	ep = strchr(cp, '>');
	if (ep != NULL)
		*ep = '\0';

	ep = strchr(cp, '@');
	if (ep != NULL)
	{
		cp = ep+1;
		if (use_flag != NULL)
			*use_flag = TRUE;
	}
		
	if (strcasecmp(cp, "MAILER_DAEMON") == 0)
		cp = "";

	(void) memset(mailfrom, '\0', mailfrom_len);
	(void) strlcpy(mailfrom, cp, mailfrom_len);
	return 0;
}

int
opendmarc_spf2_specify_ip_address(SPF_CTX_T *spfctx, char *ip_address, size_t ip_address_len)
{
	if (spfctx == NULL)
		return EINVAL;

	if (ip_address == NULL)
		return EINVAL;

	/*
	 * we don't care at this point if it is ipv6 or ipv4
	 */
	SPF_request_set_ipv4_str(spfctx->spf_request, ip_address);
	SPF_request_set_ipv6_str(spfctx->spf_request, ip_address);
	return 0;
}

int
opendmarc_spf2_test(char *ip_address, char *mail_from_domain, char *helo_domain, char *spf_record, int softfail_okay_flag, char *human_readable, size_t human_readable_len, int *used_mfrom)
{
	SPF_CTX_T *	ctx;
	int		ret;
	char 		xbuf[BUFSIZ];
	char		helo[512];
	char		mfrom[512];

	if (used_mfrom != NULL)
		*used_mfrom = FALSE;

	(void) memset(xbuf, '\0', sizeof xbuf);
	ctx = opendmarc_spf2_alloc_ctx();
	if (ctx == NULL)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, strerror(errno), human_readable_len);
		return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
	}

	if (ip_address == NULL)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, "No IP address available", human_readable_len);
		ctx = opendmarc_spf2_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_FAIL;
	}

	if (mail_from_domain == NULL && helo_domain == NULL)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, "No Domain name available to check", human_readable_len);
		ctx = opendmarc_spf2_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_FAIL;
	}

	ret = opendmarc_spf2_specify_ip_address(ctx, ip_address, strlen(ip_address));
	if (ret != 0)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, strerror(errno), human_readable_len);
		ctx = opendmarc_spf2_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
	}

	ret = opendmarc_spf2_find_mailfrom_domain(ctx, mail_from_domain, mfrom, sizeof mfrom, used_mfrom);
	if (ret != 0 || *used_mfrom == FALSE)
	{
		(void) strlcpy(helo, helo_domain, sizeof helo);
		SPF_request_set_helo_dom(ctx->spf_request, helo);
	}
	else
	{
		SPF_request_set_env_from(ctx->spf_request, mfrom);
	}
	ctx->spf_response = NULL;
	SPF_request_query_mailfrom(ctx->spf_request, &(ctx->spf_response));

	if (human_readable != NULL)
		(void) strlcpy(human_readable, SPF_strresult(SPF_response_result(ctx->spf_response)), human_readable_len);
	ctx->spf_result = SPF_response_result(ctx->spf_response);
	ret = (int) ctx->spf_result;
	ctx = opendmarc_spf2_free_ctx(ctx);

	if (ret != SPF_RESULT_PASS)
	{
		switch (ret)
		{
		    case SPF_RESULT_NONE:
			return DMARC_POLICY_SPF_OUTCOME_NONE;

		    case SPF_RESULT_NEUTRAL:
		    case SPF_RESULT_SOFTFAIL:
			if (softfail_okay_flag == TRUE)
				return DMARC_POLICY_SPF_OUTCOME_PASS;
			else
				return DMARC_POLICY_SPF_OUTCOME_FAIL;
			break;
		    case SPF_RESULT_TEMPERROR:
			return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
		}
		return DMARC_POLICY_SPF_OUTCOME_FAIL;
	}
	return DMARC_POLICY_SPF_OUTCOME_PASS;
}

#else /* HAVE_SPF2_H */

// No spf.h so no libspf2 to use so we use the internal spf check.
#ifndef TRUE
# define TRUE (1)
#endif

#ifndef FALSE
# define FALSE (0)
#endif

#ifndef MAXDNSHOSTNAME
# define MAXDNSHOSTNAME (256)
#endif
#define SPF_MAX_SPF_RECORD_LEN  (4096)

#define SPF_IN_TOKEN_NONE	(0)
#define SPF_IN_TOKEN_VERSION	(1)
#define SPF_IN_TOKEN_A		(2)
#define SPF_IN_TOKEN_MX	(3)
#define SPF_IN_TOKEN_IP4	(4)
#define SPF_IN_TOKEN_IP6	(5)
#define SPF_IN_TOKEN_PTR	(6)
#define SPF_IN_TOKEN_INCLUDE	(7)
#define SPF_IN_TOKEN_REDIRECT	(8)
#define SPF_IN_TOKEN_EXISTS	(9)
#define SPF_IN_TOKEN_EXP	(10)

const char *
opendmarc_spf_status_to_msg(SPF_CTX_T *spfctx, int status)
{
	const char *r;

	if (status != 0 && spfctx != NULL && spfctx->did_get_exp)
		return spfctx->exp_buf;

	switch (status)
	{
#define SPF_RETURN_UNDECIDED            (-1)
	    case SPF_RETURN_UNDECIDED:
		r = "Undecided";
		break;

#define SPF_RETURN_OK_PASSED            (0)
	    case SPF_RETURN_OK_PASSED:
		r = "Passed";
		break;

#define SPF_RETURN_INTERNAL	       (5)
	    case SPF_RETURN_INTERNAL:
		r = "No Domain To Check";
		break;

#define SPF_RETURN_RECORD_TOOLONG       (6)
	    case SPF_RETURN_RECORD_TOOLONG:
		r = "Record Too Big";
		break;
#define SPF_RETURN_BAD_SYNTAX_VERSION		(7)
	    case SPF_RETURN_BAD_SYNTAX_VERSION:
		r = "Bad Version";
		break;
#define SPF_RETURN_A_BUT_NO_A_RECORD    (8)
	    case SPF_RETURN_A_BUT_NO_A_RECORD:
		r = "Required 'A' lookup failed to find 'A' records";
		break;
#define SPF_RETURN_DASH_FORCED_HARD_FAIL    (9)
	    case SPF_RETURN_DASH_FORCED_HARD_FAIL:
		r = "Required 'A' but no 'A' records with -a specified";
		break;
#define SPF_RETURN_A_BUT_BAD_SYNTAX     (10)
	    case SPF_RETURN_A_BUT_BAD_SYNTAX:
		r = "IP Address Badly Formed";
		break;
#define SPF_RETURN_BAD_SYNTAX_INCLUDE   (11)
	    case SPF_RETURN_BAD_SYNTAX_INCLUDE:
		r = "'INCLUDE' Syntax Error";
		break;
#define SPF_RETURN_INCLUDE_NO_DOMAIN    (12)
	    case SPF_RETURN_INCLUDE_NO_DOMAIN:
		r = "'INCLUDE' Domain Lookup Failed";
		break;
#define SPF_RETURN_BAD_SYNTAX_REDIRECT  (13)
	    case SPF_RETURN_BAD_SYNTAX_REDIRECT:
		r = "'REDIRECT' Syntax Error";
		break;
#define SPF_RETURN_REDIRECT_NO_DOMAIN   (14)
	    case SPF_RETURN_REDIRECT_NO_DOMAIN:
		r = "'REDIRECT' Domain Lookup Failed";
		break;
#define SPF_RETURN_FAIL   (15)
	    case SPF_RETURN_FAIL:
		r = "Hard Fail: Reject";
		break;
#define SPF_RETURN_SOFTFAIL  (16)
	    case SPF_RETURN_SOFTFAIL:
		r = "Soft Fail: Subject to Policy";
		break;
#define SPF_RETURN_NEUTRAL    (17)
	    case SPF_RETURN_NEUTRAL:
		r = "Neutral Fail: Subject to Policy";
		break;
#define SPF_RETURN_UNKNOWN_KEYWORD      (18)
	    case SPF_RETURN_UNKNOWN_KEYWORD:
		r = "Unrecognized Keyword";
		break;
#define SPF_RETURN_BAD_MACRO_SYNTAX     (19)
	    case SPF_RETURN_BAD_MACRO_SYNTAX:
		r = "Macros Used But Syntax Bad";
		break;
#define SPF_RETURN_NOT_EXISTS_HARDFAIL     (20)
	    case SPF_RETURN_NOT_EXISTS_HARDFAIL:
		r = "'A' Record lookup, No Such Host";
		break;
#define SPF_RETURN_BAD_SYNTAX_EXISTS     (21)
	    case SPF_RETURN_BAD_SYNTAX_EXISTS:
		r = "'EXISTS' Omitted A domain";
		break;
#define SPF_RETURN_BAD_SYNTAX_EXP     (22)
	    case SPF_RETURN_BAD_SYNTAX_EXP:
		r = "'EXP' Bad Syntax";
		break;
#define SPF_RETURN_NOT_EXP_HARDFAIL     (23)
	    case SPF_RETURN_NOT_EXP_HARDFAIL:
		r = "'-EXP' Hard Failure";
		break;
#define SPF_RETURN_TOO_MANY_DNS_QUERIES     (24)
	    case SPF_RETURN_TOO_MANY_DNS_QUERIES:
		r = "Too Many DNS Lookups Without Success.";
		break;
	    default:
#define SPF_RETURN_INTERNAL_ERROR	(25)
		r = "Undefined Internal Error";
		break;
	}
	return r;
}

/****************************************************************
** SPF_STATUS_TO_PASS -- convert ctx->status into a decision
**	Returns 1 for pass
**	Returns 0 for fail
**	Returns -1 for maybe fail (~all means you decide)
****************************************************************/
int
opendmarc_spf_status_to_pass(int status, int none_pass)
{
	int r;

	switch (status)
	{
	    case SPF_RETURN_UNDECIDED:
		if (none_pass == 1)
			r = 1;
		else
			r = 0;
		break;
	    case SPF_RETURN_OK_PASSED:
		r = 1;
		break;
	    case SPF_RETURN_INTERNAL:
		r = 0;
		break;
	    case SPF_RETURN_RECORD_TOOLONG:
		r = 0;
		break;
	    case SPF_RETURN_BAD_SYNTAX_VERSION:
		r = 0;
		break;
	    case SPF_RETURN_A_BUT_NO_A_RECORD:
		r = 0;
		break;
	    case SPF_RETURN_DASH_FORCED_HARD_FAIL:
		r = 0;
		break;
	    case SPF_RETURN_A_BUT_BAD_SYNTAX:
		r = 0;
		break;
	    case SPF_RETURN_BAD_SYNTAX_INCLUDE:
		r = 0;
		break;
	    case SPF_RETURN_INCLUDE_NO_DOMAIN:
		r = 0;
		break;
	    case SPF_RETURN_BAD_SYNTAX_REDIRECT:
		r = 0;
		break;
	    case SPF_RETURN_REDIRECT_NO_DOMAIN:
		r = 0;
		break;
	    case SPF_RETURN_FAIL:
		r = 0;
		break;
	    case SPF_RETURN_SOFTFAIL:
		r = -1;
		break;
	    case SPF_RETURN_NEUTRAL:
		r = 1;
		break;
	    case SPF_RETURN_UNKNOWN_KEYWORD:
		r = 0;
		break;
	    case SPF_RETURN_BAD_MACRO_SYNTAX:
		r = 0;
		break;
	    case SPF_RETURN_NOT_EXISTS_HARDFAIL:
		r = 0;
		break;
	    case SPF_RETURN_BAD_SYNTAX_EXISTS:
		r = 0;
		break;
	    case SPF_RETURN_BAD_SYNTAX_EXP:
		r = 0;
		break;
	    case SPF_RETURN_TOO_MANY_DNS_QUERIES:
		r = 0;
		break;
	    case SPF_RETURN_INTERNAL_ERROR:
		r = 0;
		break;
	    default:
		r = 0;
		break;
	}
	return r;
}

/*
**  OPENDMARC_SPF_CIDR_ADDRESS -- see if an IP address is covered by a CIDR
**  	expression
**
**  Parameters:
**  	ip -- IP address to test, in network byte order
**  	cidr_addr -- CIDR expression to which to compare it
**
**  Return value:
**  	TRUE iff "ip" is inside (or equal to) "cidr_addr".
*/

int
opendmarc_spf_cidr_address(uint32_t ip, char *cidr_addr)
{
	char *cidr;
	char *cp, *ep;
	char buf[BUFSIZ];
	uint32_t i;
	uint32_t bits;
	uint32_t mask;
	uint32_t high, low;
	struct sockaddr_in sin;

	if (cidr_addr == NULL)
		return FALSE;

	(void) memset(buf, '\0', sizeof buf);
	(void) strlcpy(buf, cidr_addr, sizeof buf);

	cidr = strchr(buf, '/');
	if (cidr == NULL)
	{
		if (inet_aton(cidr_addr, &sin.sin_addr) != 0)
		{
			(void)memcpy(&low, &sin.sin_addr.s_addr, sizeof(sin.sin_addr.s_addr));
			(void)memcpy(&high, &sin.sin_addr.s_addr, sizeof(sin.sin_addr.s_addr));
			if (ip >= low && ip <= high)
				return TRUE;
		}
		return FALSE;
	}
	*cidr++ = '\0';
	bits = strtoul(cidr, NULL, 10);

	cp = buf;
	ep = strchr(buf, '.');
	if (ep == NULL)
		return FALSE;
	*ep++ = '\0';
	i = strtoul(cp, NULL, 10) << 24;

	cp = ep;
	ep = strchr(cp, '.');
	if (ep == NULL)
		return FALSE;
	*ep++ = '\0';
	i += strtoul(cp, NULL, 10) << 16;

	cp = ep;
	ep = strchr(cp, '.');
	if (ep == NULL)
		return FALSE;
	*ep++ = '\0';
	i += strtoul(cp, NULL, 10) << 8;

	cp = ep;
	i += strtoul(cp, NULL, 10);

	mask = (bits == 0) ? 0 : ~(u_long)0 << (32 - bits);

	low = i & mask;
	high = i | (~mask & 0xFFFFFFFF);

	ip = ntohl(ip);
	if (ip >= low && ip <= high)
		return TRUE;
	return FALSE;
}

/**************************************************************
** opendmarc_spf_reverse -- Reverse doman name on dot or ip address
**			on dot or colon	boundaries
**			   e.g. a.b.c becomes c.b.a
**			   and FFFF::EEEE becomes EEEE::FFFF
**			   and 12.34.56.78 becomes 78.56.34.12
** Input:
**	str	-- the string to reverse
**	buf	-- buffer to hold the reversed string
**	buflen	-- size in bytes of the buffer
** Returns:
**	NULL	On error
**	buf	On success
** Side Effects:
**	Overwrites previous contents of buf
****************************************************************/
static char *
opendmarc_spf_reverse(char *str, char *buf, size_t buflen)
{
	char *	sp;
	char *	ep;
	char *	dotp;
	int	dotorcolon = 0;
	char	dotorcolon_str[2];
	char	dupe[BUFSIZ];

	if (str == NULL || buf == NULL || buflen == 0)
		return NULL;
	if (buflen > BUFSIZ)
		buflen = BUFSIZ;

	(void) memset(buf, '\0', buflen);
	(void) memset(dupe, '\0', buflen + 1);
	(void) strlcpy(dupe, str, buflen + 1);

	dotp = strchr(dupe, '.');
	if (dotp != NULL)
		dotorcolon = '.';
	else
	{
		dotp = strchr(dupe, ':');
		if (dotp != NULL)
			dotorcolon = ':';
	}
	if (dotorcolon == 0)
		return NULL;

	dotorcolon_str[0] = dotorcolon;
	dotorcolon_str[1] = '\0';

	ep = dupe + strlen(dupe);
	/*
	 * strip tailing dotorcolons.
	 */
	do
	{
		for (sp = ep; sp >= dupe; --sp)
			if (*sp == dotorcolon)
				break;
		if (sp < dupe)
		{
			strlcat(buf, sp+1, buflen);
			break;
		}
		ep = sp;
		if (*sp == dotorcolon)
			++sp;
		if (*sp != '\0')
			strlcat(buf, sp, buflen);
		if (*ep == dotorcolon)
		{
			strlcat(buf, dotorcolon_str, buflen);
			*ep = '\0';
			--ep;
		}
	} while (sp >= dupe);
	return buf;
}

typedef struct {
	u_int   values[8];    
	int     nvalues;
} INT_ARY_T;    

typedef struct {
        char    strs[8][32];
	int     nstrs;     
} TXT_ARY_T;


static int
opendmarc_spf_ipv6_cidr_populate(TXT_ARY_T *lp, INT_ARY_T *ap)
{
	int i, f;
	int dots;

	/*
	 * Populate the base, expected variations are:
	 *	::ipv4
	 *	:FFFF:ipv4
	 *	:hex::hex: ...
	 */

	/* Clear to zero in case we got an auto array */
	for (i = 0; i < 8; ++i)
		ap->values[i] = 0;

	f = 0; /* index into the output array of values. */
	for (i = 0; i < lp->nstrs; ++i)
	{
		int value;
		int value2;
		char *cp = NULL;

		dots = 0;
		if (i == 0)
		{
			char *dp;

			/*
			 * The rightmost address might be IPv4
			 */
			for (dp = lp->strs[0]; *dp != '\0'; ++dp)
				if (*dp == '.')
					++dots;
		}

		if (i >= 0 || dots == 0)
		{
			/*
			 * No dots or not the rightmost value, then
			 * a hexedecimal value.
			 */
			if (lp->strs[i] != NULL)
			{
			ap->values[f] = strtoul(lp->strs[i], NULL, 16);
			f = f + 1;
			}
			continue;
		}

		/*
		 * From here down deals with the special case of
		 * an ipv4 address at the righthand side.
		 */
		if (dots > 3)
		{
			return errno = EINVAL;
		}
		if (dots)
		{
			cp = strrchr(lp->strs[0], '.');
			value2 = strtoul(cp+1, NULL, 10);

			for (cp = cp-1; cp > lp->strs[0]; --cp)
				if (*cp == '.')
					break;
			if (*cp == '.')
				value = strtoul(cp+1, NULL, 10);
			else
				value = strtoul(cp, NULL, 10);
			value <<= 8;
			value &= 0xFFFF;
			value += value2;
			ap->values[0] = value;
			ap->values[1] = 0;
		}
		if (dots > 1)
		{
			for (cp = cp-1; cp > lp->strs[0]; --cp)
				if (*cp == '.')
					break;
			if (*cp == '.')
				value = strtoul(cp+1, NULL, 10);
			else
				value = strtoul(cp+1, NULL, 10);
			ap->values[1] = value;
		}
		if (dots > 2)
		{
			cp = lp->strs[0];
			value = strtoul(cp, NULL, 10);
			value <<= 8;
			ap->values[1] += value;
		}
		f += 2;
		continue;
	}
	ap->nvalues = f;
	return 0;
}

static int
opendmarc_spf_ipv6_explode(char *str, TXT_ARY_T *ap)
{
	char *cp, *ep;
	int i;
	int ncolons;
	char copy[128];

	if (str == NULL || ap == NULL)
		return errno  = EINVAL;

	(void) memset(ap, '\0', sizeof(TXT_ARY_T));
	(void) memset(copy, '\0', sizeof copy);
	(void) strlcpy(copy, str, sizeof copy);

	ncolons = 0;
	for (cp = copy; *cp != '\0'; ++cp)
		if (*cp == ':')
			++ncolons;
	ncolons = 7 - ncolons;
	
	cp = copy;
	for (i = 7; i >= 0; i--)
	{
		ep = strchr(cp, ':');
		if (ep != NULL)
			*ep = '\0';
		if (strlen(cp) == 0)
		{
			(void) strlcpy((char *)ap->strs[i], "0", sizeof ap->strs[i]);
		}
		else
		{
			(void) strlcpy((char *)ap->strs[i], cp, sizeof ap->strs[i]);
		}
		if (ep && *(ep + 1) == ':' && ncolons > 0)
		{
			for (i--; i >= 0 && ncolons != 0; --ncolons, --i)
			{
				(void) strlcpy((char *)ap->strs[i], "0", sizeof ap->strs[i]);
			}
			i+= 1;
		}
		cp = ep+1;
	}
	ap->nstrs = 8 - i;
	return 0;
}

int
opendmarc_spf_ipv6_cidr_check(char *ipv6_str, char *cidr_string)
{
	int cidr_bits;
	TXT_ARY_T ipv6_ary;
	TXT_ARY_T cidr_ary;
	INT_ARY_T base_iary;
	INT_ARY_T low_iary;
	INT_ARY_T hi_iary;
	INT_ARY_T ip_iary;
	char *	cp;
	int ret;
	int i;
	int taghi, taglo;
	char cidr_str[256];

	if (ipv6_str == NULL || cidr_string == NULL)
	{
		return FALSE;
	}

	if (strchr(ipv6_str, ':') == NULL)
		return FALSE;
	if (strchr(cidr_string, ':') == NULL)
		return FALSE;

	(void) strlcpy(cidr_str, cidr_string, sizeof cidr_str);
	
	cp = strchr(cidr_str, '/');
	if (cp == NULL)
	{
		cidr_bits = 0;
	}
	else
	{
		cidr_bits = strtoul(cp+1, NULL, 10);
		*cp = '\0';
		cp = strchr(cidr_str, ':');
		if (cp == NULL)
			cidr_bits = 32 - cidr_bits;
		else
			cidr_bits = 128 - cidr_bits;
	}

	ret = opendmarc_spf_ipv6_explode(ipv6_str, &ipv6_ary);
	if (ret != 0)
	{
		return FALSE;
	}

	ret = opendmarc_spf_ipv6_explode(cidr_str, &cidr_ary);
	if (ret != 0)
	{
		return FALSE;
	}

	ret = opendmarc_spf_ipv6_cidr_populate(&cidr_ary, &base_iary);
	if (ret != 0)
	{
		return FALSE;
	}
	ret = opendmarc_spf_ipv6_cidr_populate(&ipv6_ary, &ip_iary);
	if (ret != 0)
	{
		return FALSE;
	}

	if (cidr_bits == 0)
	{
		/*
		 * Requre an exact match.
		 */
		for (i = 0; i < base_iary.nvalues; i++)
		{
			if (base_iary.values[i] != ip_iary.values[i])
			{
				return FALSE;
			}
		}
		return TRUE;
	}

	(void) memcpy(&low_iary, &base_iary, sizeof(INT_ARY_T));
	(void) memcpy(&hi_iary,  &base_iary, sizeof(INT_ARY_T));

	for (i = 0; i < 8; i++)
	{
		int twobyte_mask, tmp_mask;

		if (cidr_bits >= 16)
		{
			low_iary.values[i] = 0;
			hi_iary.values[i] = 0xFFFF;
			cidr_bits = cidr_bits - 16;
			continue;
		}
		twobyte_mask = cidr_bits % 16;
		tmp_mask = (0xFFFF << twobyte_mask);
		low_iary.values[i] = low_iary.values[i] & tmp_mask;

		tmp_mask = ((~tmp_mask) & 0xFFFF);
		hi_iary.values[i]  = hi_iary.values[i] | tmp_mask;
		if (cidr_bits < 16)
			break;
		cidr_bits = cidr_bits - 16;
	}

	taghi = FALSE;
	taglo = FALSE;

	for (i = 7; i >= 0; --i)
	{
		if (ip_iary.values[i] == low_iary.values[i] && ip_iary.values[i] == hi_iary.values[i])
		{
			continue;
		}
		if (ip_iary.values[i] == hi_iary.values[i])
		{
			taghi = TRUE;
			continue;
		}
		if (ip_iary.values[i] == low_iary.values[i])
		{
			taglo = TRUE;
			continue;
		}
		if (taghi == TRUE)
		{
			if (ip_iary.values[i] > hi_iary.values[i])
			{
				return FALSE;
			}
			continue;
		}
		if (taglo == TRUE)
		{
			if (ip_iary.values[i] < low_iary.values[i])
			{
				return FALSE;
			}
			continue;
		}
		if (ip_iary.values[i] < low_iary.values[i] || ip_iary.values[i] > hi_iary.values[i])
		{
			return FALSE;
		}
	}
	return TRUE;
}


/******************************************************************
** SPF_STRIP_DOTS -- Remove trailing and leading dots from
**			a domain name.
******************************************************************/
static char *
opendmarc_spf_strip_dots(char *str, char *dot, char *buf, size_t buflen)
{
	char *cp;
	char  dupe[BUFSIZ];

	if (buflen > BUFSIZ)
		buflen = BUFSIZ;
	if (str == NULL || buf == NULL || buflen == 0)
		return NULL;
	(void) memset(buf, '\0', buflen);
	(void) memset(dupe, '\0', buflen);
	(void) strlcpy(dupe, str, buflen);
	
	for (cp = dupe + strlen(dupe) - 1; cp > dupe; --cp)
	{
		if (*cp == '.')
			*cp = '\0';
		else
			break;
	}
	for (cp = dupe; *cp != '\0'; ++cp)
	{
		if (*cp != '.')
			break;
	}
	(void) strlcpy(buf, cp, buflen);
	return buf;
}



int
opendmarc_spf_subdomain(char *dom, char *sub)
{
	char dcopy[MAXDNSHOSTNAME];
	char scopy[MAXDNSHOSTNAME];
	char scratch[MAXDNSHOSTNAME];
	char *cp;
	int   dlen;
	int   slen;

	if (dom == NULL || sub == NULL)
		return FALSE;
	(void) memset(dcopy, '\0', sizeof dcopy);
	(void) memset(scopy, '\0', sizeof scopy);
	(void) memset(scratch, '\0', sizeof scratch);

	cp = opendmarc_spf_strip_dots(dom, ".", scratch, sizeof scratch);
	if (cp == NULL)
		return FALSE;
	cp = opendmarc_spf_reverse(scratch, dcopy, sizeof dcopy);
	if (cp == NULL)
		return FALSE;

	cp = opendmarc_spf_strip_dots(sub, ".", scratch, sizeof scratch);
	if (cp == NULL)
		return FALSE;
	cp = opendmarc_spf_reverse(scratch, scopy, sizeof scopy);
	if (cp == NULL)
		return FALSE;

	(void) strlcat(dcopy, ".", sizeof dcopy);
	(void) strlcat(scopy, ".", sizeof scopy);

	dlen = strlen(dcopy);
	slen = strlen(scopy);

	if (dlen == slen)
	{
		if (strcasecmp(dcopy, scopy) == 0)
			return TRUE;
		return FALSE;
	}
	if (strncasecmp(dcopy, scopy, dlen) == 0)
		return TRUE;
	return FALSE;
}
static int
opendmarc_spf_ptr_domain(SPF_CTX_T *spfctx, char *domain)
{
	char **	dry = NULL;
	int	dry_len = 0;
	char **	dpp;
	char **	ary = NULL;
	int	ary_len = 0;
	char **	app;
	char **	nary = NULL;
	int	nary_len = 0;
	char **	npp;
	int	good = FALSE;;

	if (spfctx->validated_domain[0] != '\0')
		return TRUE;
	dry = opendmarc_spf_dns_lookup_ptr(spfctx->ip_address, dry, &dry_len);

	/*
	 * There can be muiltple host names returned.
	 */
	for (dpp = dry; dpp != NULL && *dpp != NULL; ++dpp)
	{
		ary = opendmarc_spf_dns_lookup_a(*dpp, ary, &ary_len);
		if (ary == NULL)
			continue;

		/*
		 * Compare the addresses returned for that host name
		 * to the specified IP address and if it compares
		 * save the host name for later.
		 */
		for (app = ary; app != NULL && *app != NULL; ++app)
		{
			if (strcasecmp(*app, spfctx->ip_address) == 0)
			{
				nary = opendmarc_util_pushnargv(*dpp, nary, &nary_len);
				break;
			}
		}
		if (nary == NULL)
			break;
		for (npp = nary; *npp != NULL; ++npp)
		{
			char *dp;

			if (domain == NULL)
				dp = spfctx->mailfrom_domain;
			else
				dp = domain;
			if (opendmarc_spf_subdomain(dp, *dpp) == TRUE)
			{
				(void) strlcpy(spfctx->validated_domain, *dpp, sizeof spfctx->validated_domain);
				good = TRUE;
				break;
			}
		}
		nary = opendmarc_util_freenargv(nary, &nary_len);
		if (good == TRUE)
			break;
	}
	dry = opendmarc_util_freenargv(dry, &dry_len);
	return good;
}

static char *
opendmarc_spf_macro_expand(SPF_CTX_T *spfctx, char *str, char *buf, size_t buflen, int is_exp)
{
	char *sp;
	char *xp;
	char *ep;
	char *bp;
	char  scratch[MAXDNSHOSTNAME];
	time_t t;
	int   num;
	int   rev;

	if (spfctx == NULL || str == NULL || buf == NULL || strlen(str) > buflen)
	{
		return NULL;
	}
	sp = str;
	ep = str + strlen(str);
	(void) memset(buf, '\0', buflen);
	bp = buf;

	for (sp = str; sp < ep; )
	{
		if (*sp != '%')
		{
			*bp++ = *sp++;
			continue;
		}
		++sp;
		switch ((int)*sp)
		{
		    case '%':
			*bp++ = *sp++;
			continue;
		    case '_':
			*bp++ = ' ';
			++sp;
			continue;
		    case '-':
			*bp++ = '%';
			*bp++ = '2';
			*bp++ = '0';
			++sp;
			continue;
		    case '{':
			break;
		    default:
			return NULL;
		}
		++sp;
		num = 0;
		rev = FALSE;
		xp = sp+1;
		if (*xp == 'r')
		{
			rev = TRUE;
			++xp;
		}
		if (isdigit((int)*xp))
		{
			num = strtoul(xp, &xp, 10);
		}
		char * cp;
		switch ((int)*sp)
		{
		    case 's':
			if (rev == TRUE)
				(void) opendmarc_spf_reverse(spfctx->mailfrom_domain, scratch, MAXDNSHOSTNAME);
			else
				(void) strlcpy(scratch, spfctx->mailfrom_domain, MAXDNSHOSTNAME);
			if (num > 0 && num < MAXDNSHOSTNAME)
				scratch[num] = '\0';
			for (cp = scratch; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'l':
			(void) strlcpy(scratch, spfctx->mailfrom_addr, MAXDNSHOSTNAME);
			cp = strchr(scratch, '@');
			if (cp != NULL)
				*cp = '\0';
			if (num > 0 && num < MAXDNSHOSTNAME)
				scratch[num] = '\0';
			for (cp = scratch; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'o':
			(void) strlcpy(scratch, spfctx->mailfrom_addr, MAXDNSHOSTNAME);
			cp = strchr(scratch, '@');
			if (cp != NULL)
				++cp;
			else
				cp = scratch;
			if (num > 0 && num < (MAXDNSHOSTNAME - (cp - scratch)))
				cp[num] = '\0';
			for (; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'd':
			if (rev == TRUE)
				(void) opendmarc_spf_reverse(spfctx->mailfrom_domain, scratch, MAXDNSHOSTNAME);
			else
				(void) strlcpy(scratch, spfctx->mailfrom_domain, MAXDNSHOSTNAME);
			if (num > 0 && num < MAXDNSHOSTNAME)
				scratch[num] = '\0';
			for (cp = scratch; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'i':
			if (rev == TRUE)
				(void) opendmarc_spf_reverse(spfctx->ip_address, scratch, MAXDNSHOSTNAME);
			else
			if (num > 0 && num < MAXDNSHOSTNAME)
				scratch[num] = '\0';
			for (cp = scratch; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'h':
			if (rev == TRUE)
				(void) opendmarc_spf_reverse(spfctx->helo_domain, scratch, MAXDNSHOSTNAME);
			else
				(void) strlcpy(scratch, spfctx->helo_domain, MAXDNSHOSTNAME);
			if (num > 0 && num < MAXDNSHOSTNAME)
				scratch[num] = '\0';
			for (cp = scratch; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'v':
			/* if ip is ipv6 use "ip6" instead */
			for (cp = "in-addr"; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'p':
			if (spfctx->validated_domain[0] == '\0')
				(void) opendmarc_spf_ptr_domain(spfctx, NULL);
			if (rev == TRUE)
				(void) opendmarc_spf_reverse(spfctx->validated_domain, scratch, MAXDNSHOSTNAME);
			else
				(void) strlcpy(scratch, spfctx->validated_domain, MAXDNSHOSTNAME);
			if (num > 0 && num < MAXDNSHOSTNAME)
				scratch[num] = '\0';
			for (cp = scratch; *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'c':
			if (is_exp == FALSE)
				return NULL;
			if (rev == TRUE)
				(void) opendmarc_spf_reverse(spfctx->ip_address, scratch, MAXDNSHOSTNAME);
			else
				(void) strlcpy(scratch, spfctx->ip_address, MAXDNSHOSTNAME);
			if (num > 0 && num < MAXDNSHOSTNAME)
				scratch[num] = '\0';
			for (cp = scratch;  *cp != '\0'; )
				*bp++ = *cp++;
			break;
		    case 'r':
			/* do rev and num apply to this one? */
			if (is_exp == FALSE)
				return NULL;
			if (gethostname(scratch, sizeof scratch) == 0)
			{
				for (cp = scratch;  *cp != '\0'; )
					*bp++ = *cp++;
			}
			break;
		    case 't':
			/* do rev and num apply to this one? */
			if (is_exp == FALSE)
				return NULL;
			t = time(NULL);
			(void) opendmarc_util_ultoa(t, scratch, sizeof scratch);
			for (cp = scratch;  *cp != '\0'; )
				*bp++ = *cp++;
			break;
		}
		if (*xp != '}')
			return NULL;
		sp = xp+1;
		continue;
	}
	*bp++ = '\0';
	return buf;
}


/**************************************************************
** __xbuf_append - append multiple arguments to buf
**
** Arguments:
**	buf			-- buffer to write to
**	buf_len	-- size of buffer
**	...				-- NULL-terminated list of const char * that should be appended
*/
static void __strlcat_multi(char *buf, size_t buf_len, ...)
{
	va_list ap;
	const char *curr = NULL;
	va_start(ap, buf_len);
	while (NULL != (curr = va_arg(ap, const char *))) {
		(void) strlcat(buf, curr, buf_len);
	}
}
/* define a macro to avoid forgetting the final NULL */
#define strlcat_multi(buf, buf_len, ...) __strlcat_multi(buf, buf_len, __VA_ARGS__, NULL)

/***************************************************************
** libspf_parse -- parse the record
**
** Arguments:
**	ctx		-- SPF_CTX_T
**	xbuf		-- buffer into which errors are written.
**	xbuf_len	-- size of buffer
**
** Returns:
**	spfctx->status
**
** Side Effects:
**	Makes a connections to the local name server and blocks
**	on each waiting for a reply.
**
***************************************************************/
#define MAX_SPF_STACK_DEPTH (10)
#define MAX_SPF_DNS_LOOKUPS (10)
typedef struct {
	char domain[MAXDNSHOSTNAME];
	char spf[SPF_MAX_SPF_RECORD_LEN];
	char *sp;
	char *ep;
	char *esp;
	char redirect[MAXDNSHOSTNAME];
	char prefix;
	int result;
} SPF_STACK_T;

#define SPF_SP  (stack[s].sp)
#define SPF_EP  (stack[s].ep)
#define SPF_ESP (stack[s].esp)
#define PUSHLINE i = spfctx->nlines; if (i < MAX_SPF_STACK_DEPTH) { spfctx->lines[i] = strdup(xbuf); spfctx->nlines = ++i; }
int
opendmarc_spf_parse(SPF_CTX_T *spfctx, int dns_count, char *xbuf, size_t xbuf_len)
{
	char ipnum[64];
	char *vp	= NULL;
	int   i;
	size_t len;
	u_long ip	= 0;
	int split	= 0;
#define SPLIT_COLON (1)
#define SPLIT_EQUAL (2)
#define SPLIT_SLASH (3)
	SPF_STACK_T stack[MAX_SPF_STACK_DEPTH];
	int s = 0;
	int up = FALSE;
	int ret;

	spfctx->in_token = SPF_IN_TOKEN_NONE;
	if (spfctx == NULL)
	{
		(void) strlcat(xbuf, "Oddly the context was NULL: FAILED", xbuf_len);
		PUSHLINE
		return spfctx->status = SPF_RETURN_INTERNAL;
	}
	if (spfctx->mailfrom_domain[0] == '\0')
	{
		if (spfctx->helo_domain[0] == '\0')
		{
			(void) strlcat(xbuf, "Spf present but oddly no domain specified: FAILED", xbuf_len);
			PUSHLINE
			return spfctx->status = SPF_RETURN_INTERNAL;
		}
		(void) strlcpy(spfctx->mailfrom_domain, spfctx->helo_domain, sizeof spfctx->mailfrom_domain);
	}
	if (spfctx->spf_record[0] == '\0')
	{
		(void) strlcat(xbuf, "Spf TXT record existed, but was empty: FAILED", xbuf_len);
		PUSHLINE
		return spfctx->status = SPF_RETURN_INTERNAL;
	}
	if (spfctx->ip_address[0] == '\0')
	{
		(void) strlcat(xbuf, "Spf present but no IP address to check: FAILED", xbuf_len);
		PUSHLINE
		return spfctx->status = SPF_RETURN_INTERNAL;
	}
	len = strlen(spfctx->spf_record);
	if (len >= SPF_MAX_SPF_RECORD_LEN -1)
	{
		(void) strlcat(xbuf, "Spf TXT record existed, but was absurdly large: FAILED", xbuf_len);
		PUSHLINE
		return spfctx->status = SPF_RETURN_RECORD_TOOLONG;
	}

	(void) memset(stack[s].domain, '\0', MAXDNSHOSTNAME);
	(void) strlcpy(stack[s].domain, spfctx->mailfrom_domain, MAXDNSHOSTNAME);

	(void) memset(ipnum, '\0', sizeof ipnum);
	(void) strlcpy(ipnum, spfctx->ip_address, sizeof ipnum);
	ip = inet_addr(ipnum);

	(void) strlcpy(stack[s].spf, spfctx->spf_record, SPF_MAX_SPF_RECORD_LEN);
	SPF_SP  = stack[s].spf;
	SPF_EP  = stack[s].spf + strlen(stack[s].spf);
	SPF_ESP = stack[s].spf - 1;
	stack[s].result = SPF_RETURN_UNDECIDED;
	up = TRUE;

	while (s >= 0)
	{
		if (up == TRUE)
		{
			(void) memset(xbuf, '\0', xbuf_len);
			(void) strlcpy(xbuf, stack[s].domain, xbuf_len);
			strlcat_multi(xbuf, xbuf_len, ": ", stack[s].spf);
			PUSHLINE
		}

		for (;;)
		{
			if (dns_count > MAX_SPF_DNS_LOOKUPS)
			{
				(void) strlcat(xbuf, " Too Many DNS queries (10 max): FAILED", xbuf_len);
				PUSHLINE
				return spfctx->status = SPF_RETURN_TOO_MANY_DNS_QUERIES;
			}

			if (stack[s].result != SPF_RETURN_UNDECIDED) {

				/* apply qualifier if we had a match or error in the last iteration */
				switch (stack[s].result) {
					/* on match, check qualfier */
					case SPF_RETURN_OK_PASSED:
						switch(stack[s].prefix) {
							case '~':
								strlcat_multi(xbuf, xbuf_len, " (qualifier '~') --> ", s == 0 ? "SOFTFAIL" : "NOMATCH");
								stack[s].result = SPF_RETURN_SOFTFAIL;
								break;
							case '-':
								strlcat_multi(xbuf, xbuf_len, " (qualifier '-') --> ", s == 0 ? "FAIL" : "NOMATCH");
								stack[s].result = SPF_RETURN_FAIL;
								break;
							case '?':
								strlcat_multi(xbuf, xbuf_len, " (qualifier '?') --> ", s == 0 ? "NEUTRAL" : "NOMATCH");
								stack[s].result = SPF_RETURN_NEUTRAL;
								break;
							case '+':
							case '\0':
								strlcat_multi(xbuf, xbuf_len, " (qualifier ", stack[s].result == '\0' ? "<none>" : "'+'", ") --> ", s == 0 ? "PASS" : "MATCH");
								stack[s].result = SPF_RETURN_OK_PASSED;
								break;
						}
				}

				/* evaluate result in context of an include:
				 *   pass -> "match"; also apply qualifiers of the include,
				 *   fail/neutral/softfail -> "nomatch",
				 *   tmperror -> tmperror,
				 *   permerror -> permerror
				 **/
				while (s > 0 && stack[s].result != SPF_RETURN_UNDECIDED) {
					int result = stack[s].result;
					s--;
					up = FALSE;
					switch (result) {
						case SPF_RETURN_OK_PASSED:
							switch(stack[s].prefix) {
								case '~':
									(void) strlcat(xbuf, " include: SOFTFAIL", xbuf_len);
									stack[s].result = SPF_RETURN_SOFTFAIL;
									break;
								case '-':
									(void) strlcat(xbuf, " include: FAIL", xbuf_len);
									stack[s].result = SPF_RETURN_FAIL;
									break;
								case '?':
									(void) strlcat(xbuf, " include: NEUTRAL", xbuf_len);
									stack[s].result = SPF_RETURN_NEUTRAL;
									break;
								case '+':
								case '\0':
									(void) strlcat(xbuf, " include: PASS", xbuf_len);
									stack[s].result = SPF_RETURN_OK_PASSED;
									break;
								default:
									(void) strlcat(xbuf, " include: INTERNAL ERROR", xbuf_len);
									stack[s].result = SPF_RETURN_INTERNAL_ERROR;
									break;
							}
							break;
						case SPF_RETURN_FAIL:
						case SPF_RETURN_SOFTFAIL:
						case SPF_RETURN_NEUTRAL:
							(void) strlcat(xbuf, " include: NOMATCH", xbuf_len);
							/* "no match" --> do not change the UNDECIDED result
							 *  and continue processing where the include left off */
							break;
						default:
							/* all other error (!) cases (temperror/permerror) are directly returned as they are */
							(void) strlcat(xbuf, " include: PROPAGATE ERROR", xbuf_len);
							stack[s].result = result;
              break;
					}
				}

				/* if we have a result at the toplevel, return it, otherwise,
				 * continue where we stopped */
				if (s == 0 && stack[s].result != SPF_RETURN_UNDECIDED) {
					PUSHLINE
					return spfctx->status = stack[s].result;
				}
			}

			int reached_end = FALSE;
			if (SPF_ESP >= SPF_EP-1) {
				reached_end = TRUE;
			} else {
				SPF_SP = SPF_ESP + 1;
				while (isspace((int)*SPF_SP) && *SPF_SP != '\0' && SPF_SP < SPF_EP)
					++SPF_SP;
				if (*SPF_SP == '\0' || SPF_SP >= SPF_EP) {
					reached_end = TRUE;
				} else {
					SPF_ESP = SPF_SP;
					while(! isspace((int)*SPF_ESP) && *SPF_ESP != '\0' && SPF_ESP < SPF_EP)
						++SPF_ESP;
					if (SPF_ESP > SPF_EP) {
						reached_end = TRUE;
					} else {
						*SPF_ESP = '\0';
					}
				}
			}

			if (reached_end) {
				if (stack[s].redirect[0] != '\0') {
					char *  spf_ret;
					char	spfbuf[SPF_MAX_SPF_RECORD_LEN];
					char	cname[MAXDNSHOSTNAME];
					int	reply;
					/* redirect */
					spf_ret = opendmarc_spf_dns_get_record(stack[s].redirect, &reply, spfbuf, sizeof spfbuf, cname, sizeof cname, TRUE);
					if (spf_ret == NULL)
					{
						strlcat_multi(xbuf, xbuf_len, vp, " lacked an SPF record: FAILED");
						PUSHLINE
						stack[s].result = SPF_RETURN_BAD_SYNTAX_REDIRECT;
					}
					else
					{
						(void) memset(stack[s].domain, '\0', MAXDNSHOSTNAME);
						(void) strlcpy(stack[s].domain, stack[s].redirect, MAXDNSHOSTNAME);
						(void) memset(stack[s].spf, '\0', SPF_MAX_SPF_RECORD_LEN);
						(void) strlcpy(stack[s].spf, spfbuf, SPF_MAX_SPF_RECORD_LEN);
						SPF_SP  = stack[s].spf;
						SPF_EP  = stack[s].spf + strlen(stack[s].spf);
						SPF_ESP = stack[s].spf - 1;
						stack[s].result = SPF_RETURN_UNDECIDED;
						up = TRUE;

						/* start parsing loop from beginning */
						break;
					}
				} else {
					--s;
					up = FALSE;
					break;
				}
			}

			/* show each step */
			(void) memset(xbuf, '\0', xbuf_len);
			(void) strlcpy(xbuf, stack[s].domain, xbuf_len);
			(void) strlcat(xbuf, ": ", xbuf_len);

			/* remember current qualifier for next iteration to decide handling of a MATCH */
			stack[s].prefix = '\0';
			if (*SPF_SP == '+' || *SPF_SP == '?' || *SPF_SP == '~' || *SPF_SP == '-')
			{
				stack[s].prefix = *SPF_SP;
				++SPF_SP;
			}

			/* split at any =, /, or : into name=sp, value=vp */
			vp = strchr(SPF_SP, '=');
			if (vp != NULL)
			{
				split = SPLIT_EQUAL;
				*vp++ = '\0';
			}
			else
			{
				vp = strchr(SPF_SP, ':');
				if (vp != NULL)
				{
					split = SPLIT_COLON;
					*vp++ = '\0';
				}
				else
				{
					vp = strchr(SPF_SP, '/');
					if (vp != NULL)
					{
						split = SPLIT_SLASH;
						*vp++ = '\0';
					}
					else
					{
						vp = NULL;
					}
				}
			}

			if (strcasecmp(SPF_SP, "v") == 0)
			{
				spfctx->in_token = SPF_IN_TOKEN_VERSION;
				if (vp == NULL || strcasecmp(vp, "spf1") != 0)
				{
					(void) strlcat(xbuf, " Expected \"v=spf1\": FAILED", xbuf_len);
					PUSHLINE
					stack[s].result = SPF_RETURN_BAD_SYNTAX_VERSION;
				}
			}
			else if (strncasecmp(SPF_SP, "spf2.0", 6) == 0)
			{
				/* accept deprecated syntax */
			}
			else if (strcasecmp("a", SPF_SP) == 0 || strcasecmp("ip4", SPF_SP) == 0)
			{
				char **	ary = NULL;
				int	ary_len = 0;
				char **	app;
				char 	abuf[BUFSIZ];

				if (strcasecmp(SPF_SP, "a") == 0 && (vp == NULL || split == SPLIT_SLASH))
				{

					/*
					 * Don't know what to do with a/24.
					 * look up the a, and do each address/24?
					 */
					if (ary != NULL)
						ary = opendmarc_util_freenargv(ary, &ary_len);
					++dns_count;
					ary = opendmarc_spf_dns_lookup_a(stack[s].domain, ary, &ary_len);
					if (ary != NULL)
					{
						int match = FALSE;
						for (app = ary; *app != NULL && !match; ++app)
						{
							(void) memset(abuf, '\0', sizeof abuf);
							(void) strlcpy(abuf, *app, sizeof abuf);
							if (vp != NULL)
							{
								strlcat_multi(abuf, sizeof abuf, "/", vp);
							}
							spfctx->iplist = opendmarc_util_pushnargv(abuf, spfctx->iplist, &(spfctx->ipcount));
							if (opendmarc_spf_cidr_address(ip, abuf) == TRUE)
							{
								strlcat_multi(xbuf, xbuf_len, " ", ipnum, " was found in ", abuf, ": MATCH");
								ary = opendmarc_util_freenargv(ary, &ary_len);
								stack[s].result = SPF_RETURN_OK_PASSED;
								match = TRUE;
							}
						}
						ary = opendmarc_util_freenargv(ary, &ary_len);
					}
					else
					{
						strlcat_multi(xbuf, xbuf_len, " ", stack[s].domain, " had no A records: FAILED");
						PUSHLINE
						stack[s].result = SPF_RETURN_A_BUT_NO_A_RECORD;
					}
				}
				else if (strcasecmp("a", SPF_SP) == 0 && vp != NULL)
				{
					char *  slashp  = NULL;
					char ** a_ary   = NULL;
					int	a_ary_len = 0;
					char ** a_app   = NULL;
					char    a_abuf[BUFSIZ];
					(void) opendmarc_spf_macro_expand(spfctx, vp, a_abuf, sizeof a_abuf, FALSE);
					++dns_count;
					a_ary = (char **)opendmarc_spf_dns_lookup_a(a_abuf, a_ary, &a_ary_len);
					if (a_ary == NULL)
					{
						strlcat_multi(xbuf, xbuf_len, " ", vp, "had no A records: FAILED");
						PUSHLINE
						stack[s].result = SPF_RETURN_A_BUT_NO_A_RECORD;
					}
					else
					{
						int match = FALSE;
						for (a_app = a_ary; *a_app != NULL && !match; ++a_app)
						{
							(void) memset(a_abuf, '\0', sizeof a_abuf);
							(void) strlcpy(a_abuf, *a_app, sizeof a_abuf);
							if (slashp != NULL)
							{
								strlcat_multi(a_abuf, sizeof a_abuf, "/", slashp+1);
							}
							spfctx->iplist = opendmarc_util_pushnargv(a_abuf, spfctx->iplist, &(spfctx->ipcount));
							if (opendmarc_spf_cidr_address(ip, a_abuf) == TRUE)
							{
								strlcat_multi(xbuf, xbuf_len, " ", ipnum, " was found: MATCH");
								a_ary = opendmarc_util_freenargv(a_ary, &ary_len);
								stack[s].result = SPF_RETURN_OK_PASSED;
								match = TRUE;
							}
						}
						a_ary = opendmarc_util_freenargv(a_ary, &ary_len);
					}
				}
				else if (strcasecmp("ip4", SPF_SP) == 0 && vp != NULL)
				{
					spfctx->iplist = opendmarc_util_pushnargv(vp, spfctx->iplist, &(spfctx->ipcount));
					ret = opendmarc_spf_cidr_address(ip, vp);
					if (ret == TRUE)
					{
						strlcat_multi(xbuf, xbuf_len, " ", ipnum, " was found: MATCH");
						stack[s].result = SPF_RETURN_OK_PASSED;
					}
				}
				else if (vp == NULL)
				{
					vp = "<nil>";
					strlcat_multi(xbuf, xbuf_len, " ", vp, " Badly formed: FAILED");
					PUSHLINE
					stack[s].result = SPF_RETURN_A_BUT_BAD_SYNTAX;
				}
			}
			else if (strcasecmp("mx", SPF_SP) == 0)
			{
				char **	ary = NULL;
				int	ary_len = 0;
				char **	app = NULL;
				char   	mxbuf[BUFSIZ];

				if (vp != NULL && split != SPLIT_SLASH)
					(void) opendmarc_spf_macro_expand(spfctx, vp, mxbuf, sizeof mxbuf, FALSE);
				else
					(void) opendmarc_spf_macro_expand(spfctx, stack[s].domain, mxbuf, sizeof mxbuf, FALSE);
				++dns_count;
				ary = opendmarc_spf_dns_lookup_mx(mxbuf, ary, &ary_len);
				if (ary == NULL)
				{
					strlcat_multi(xbuf, xbuf_len, mxbuf, ": MX listed but no MX records");
					PUSHLINE
				}
				else
				{
					int match = FALSE;
					for (app = ary; *app != NULL && !match; ++app)
					{
						spfctx->iplist = opendmarc_util_pushnargv(*app, spfctx->iplist, &(spfctx->ipcount));
						if (opendmarc_spf_cidr_address(ip, *app) == TRUE)
						{
							strlcat_multi(xbuf, xbuf_len, " ", ipnum, " was found in MX record: MATCH");
							ary = opendmarc_util_freenargv(ary, &ary_len);
							stack[s].result = SPF_RETURN_OK_PASSED;
							match = TRUE;
						}
					}
					ary = opendmarc_util_freenargv(ary, &ary_len);
				}
			}
			else if (strcasecmp("include", SPF_SP) == 0)
			{
				char	*spf_ret;
				char	query[MAXDNSHOSTNAME];
				int	reply;
				char	cname[128];
				char	spfbuf[BUFSIZ];

				if (vp == NULL || strlen(vp) == 0)
				{
					(void) strlcat(xbuf, "\"include:\" Lacked a domain specification.", xbuf_len);
					PUSHLINE
					stack[s].result = SPF_RETURN_BAD_SYNTAX_INCLUDE;
				}
				else
				{
					(void) memset(query, '\0', sizeof query);
					(void) strlcpy(query, vp, sizeof query);
					(void) memset(cname, '\0', sizeof cname);
					(void) memset(spfbuf, '\0', sizeof spfbuf);
					++dns_count;
					spf_ret = opendmarc_spf_dns_get_record(query, &reply, spfbuf, sizeof spfbuf, cname, sizeof cname, TRUE);
					if (spf_ret == NULL)
					{
						strlcat_multi(xbuf, xbuf_len, vp, " lacked an SPF record: FAILED");
						PUSHLINE
						stack[s].result = SPF_RETURN_INCLUDE_NO_DOMAIN;
					}
					else if (s+1 >= MAX_SPF_STACK_DEPTH)
					{
						char nbuf[16];
						(void) opendmarc_util_ultoa(MAX_SPF_STACK_DEPTH, nbuf, sizeof nbuf);
						strlcat_multi(xbuf, xbuf_len, stack[s].domain, " Too many levels of includes, ", nbuf, " Max");
						PUSHLINE
					}
					else
					{
						i = 0;
						if (s > 0) {
							for (i = 0; i < s; i++)
							{
								if (strcasecmp(vp, stack[i].domain) == 0)
									break;
							}
						}

						if (i < s)
						{
							strlcat_multi(xbuf, xbuf_len, query, " Include LOOP detected and suppressed");
							PUSHLINE
						}
						else
						{
							s += 1;
							up = TRUE;
							(void) memset(stack[s].domain, '\0', MAXDNSHOSTNAME);
							(void) strlcpy(stack[s].domain, vp, MAXDNSHOSTNAME);
							(void) memset(stack[s].spf, '\0', SPF_MAX_SPF_RECORD_LEN);
							(void) strlcpy(stack[s].spf, spfbuf, SPF_MAX_SPF_RECORD_LEN);
							(void) memset(stack[s].redirect, '\0', MAXDNSHOSTNAME);
							SPF_SP  = stack[s].spf;
							SPF_EP  = stack[s].spf + strlen(stack[s].spf);
							SPF_ESP = stack[s].spf - 1;
							stack[s].prefix = '\0';
							stack[s].result = SPF_RETURN_UNDECIDED;

							/* break out of inner record-parsing loop */
							break;
						}
					}
				}
			}
			else if (strcasecmp("all", SPF_SP) == 0)
			{

				(void) memset(xbuf, '\0', xbuf_len);
				(void) strlcpy(xbuf, stack[s].domain, xbuf_len);
				strlcat_multi(xbuf, xbuf_len, ": ", ipnum, " matched by all: MATCH");
				stack[s].result = SPF_RETURN_OK_PASSED;
			}
			else if (strcasecmp("ip6", SPF_SP) == 0)
			{
				int ret;
				/*
				 * Open issue: Should we convert an ipv4 address in spfctx->ip_address
				 * into ipv6 for this check? e.g. 1.2.3.4 -> :FFFF:1.2.3.4
				 */
				spfctx->iplist = opendmarc_util_pushnargv(vp, spfctx->iplist, &(spfctx->ipcount));
				ret = opendmarc_spf_ipv6_cidr_check(spfctx->ip_address, vp);
				if (ret == TRUE)
				{
					strlcat_multi(xbuf, xbuf_len, " ", ipnum, " was found: MATCH");
					stack[s].result = spfctx->status = SPF_RETURN_OK_PASSED;
				}
			}
			else if (strcasecmp("ptr", SPF_SP) == 0)
			{
				int	good;

				good = opendmarc_spf_ptr_domain(spfctx, vp);
				if (good == TRUE)
				{
					strlcat_multi(xbuf, xbuf_len, ": ", ipnum, " matches ptr: ", vp, ": MATCH");
					stack[s].result = SPF_RETURN_OK_PASSED;
				}
			}
			else if (strcasecmp("exists", SPF_SP) == 0)
			{
				char *	xp;
				char **	ary	 = NULL;
				int	ary_len	 = 0;
				char **	app;

				if (vp == NULL || strlen(vp) == 0)
				{
					(void) strlcpy(xbuf, "\"exists:\" Lacked a domain specification.", xbuf_len);
					PUSHLINE
					stack[s].result = SPF_RETURN_BAD_SYNTAX_EXISTS;
				}
				else
				{
					/* see http://old.openspf.org/macros.html for macros */
					/* altavista.net uses +exists:CL.%{i}.FR.%{s}.HE.%{h}.null.spf.altavista.com */
					xp = opendmarc_spf_macro_expand(spfctx, vp, xbuf, xbuf_len, TRUE);
					if (xp == NULL)
					{
						(void) strlcpy(xbuf, "\"exists:\" record had syntactially bad macros:" , xbuf_len);
						strlcat_multi(xbuf, xbuf_len, vp, ": FAILED");
						PUSHLINE
						stack[s].result = SPF_RETURN_BAD_MACRO_SYNTAX;
					}
					else
					{
						++dns_count;
						if (ary != NULL)
							ary = opendmarc_util_freenargv(ary, &ary_len);
						ary = opendmarc_spf_dns_lookup_a(xbuf, ary, &ary_len);
						if (ary != NULL)
						{
							int match = FALSE;
							for (app = ary; *app != NULL && !match; ++app)
							{
								if (strcmp(spfctx->ip_address, *app) == 0)
								{
									(void) strlcpy(xbuf, "\"exists:\" record lookup: ", xbuf_len);
									strlcat_multi(xbuf, xbuf_len, vp, " existed: MATCH");
									stack[s].result = SPF_RETURN_OK_PASSED;
									match = TRUE;
								}
							}
							ary = opendmarc_util_freenargv(ary, &ary_len);
						}
					}
				}
			}
			else if (strcasecmp("exp", SPF_SP) == 0)
			{
				char *	xp;

				if (vp == NULL || strlen(vp) == 0)
				{
					(void) strlcpy(xbuf, "\"exp:\" Lacked a domain specification.", xbuf_len);
					PUSHLINE
					stack[s].result = SPF_RETURN_BAD_SYNTAX_EXP;
				}
				else
				{
					xp = opendmarc_spf_macro_expand(spfctx, vp, xbuf, xbuf_len, FALSE);
					if (xp == NULL)
					{
						(void) strlcpy(xbuf, "\"exists:\" record had syntactially bad macros:" , xbuf_len);
						strlcat_multi(xbuf, xbuf_len, vp, ": FAILED");
						PUSHLINE
						stack[s].result = SPF_RETURN_BAD_MACRO_SYNTAX;
					}
					else
					{
						(void) memset(spfctx->exp_buf, '\0', sizeof spfctx->exp_buf);
						(void) strlcpy(spfctx->exp_buf, xp, sizeof spfctx->exp_buf);
						spfctx->did_get_exp = TRUE;
					}
				}
			}
			else if (strcasecmp("redirect", SPF_SP) == 0)
			{
				/*
				 * Some people think that redirect and include are the same.
				 * Rather than fail due to that belief, there is really no harm
				 * in treating them the same.
				 */
				char *	xp;
				char	query[MAXDNSHOSTNAME];

				if (vp == NULL)
				{
					(void) strlcat(xbuf, " Lacked a domain specification: FAILED", xbuf_len);
					PUSHLINE
					stack[s].result = SPF_RETURN_REDIRECT_NO_DOMAIN;
				}
				else
				{
					(void) memset(query, '\0', sizeof query);
					xp = opendmarc_spf_macro_expand(spfctx, vp, query, sizeof query, TRUE);
					if (xp == NULL)
					{
						(void) strlcpy(xbuf, "\"redirect:\" record had syntactially bad macros:" , xbuf_len);
						strlcat_multi(xbuf, xbuf_len, vp, ": FAILED");
						PUSHLINE
						stack[s].result = SPF_RETURN_BAD_MACRO_SYNTAX;
					}
					else
					{
						++dns_count;
						(void) strlcpy(stack[s].redirect, query, MAXDNSHOSTNAME);
					}
				}
			}
			else if (strlen(SPF_SP) > 0)
			{
				strlcat_multi(xbuf, xbuf_len, "\"", SPF_SP, "\": Unrecognized SPF keyword, WARNING");
				PUSHLINE
				/* return spfctx->status = SPF_RETURN_UNKNOWN_KEYWORD; */
			}
		}
	}
	return spfctx->status;
}

SPF_CTX_T *
opendmarc_spf_alloc_ctx()
{
	SPF_CTX_T *spfctx = NULL;

	spfctx = malloc(sizeof(SPF_CTX_T));
	if (spfctx == NULL)
		return NULL;

	(void) memset(spfctx, '\0', sizeof(SPF_CTX_T));
	spfctx->status = SPF_RETURN_UNDECIDED;
	return spfctx;
}

SPF_CTX_T *
opendmarc_spf_free_ctx(SPF_CTX_T *spfctx)
{
	int i;

	if (spfctx == NULL)
		return spfctx;

	for (i = 0; i < spfctx->nlines; i++)
	{
		if (spfctx->lines[i] != NULL)
		{
			(void) free(spfctx->lines[i]);
		}
	}
	spfctx->iplist = opendmarc_util_freenargv(spfctx->iplist, &(spfctx->ipcount));
	(void) free(spfctx);
	spfctx = NULL;
	return spfctx;
}

int
opendmarc_spf_specify_ip_address(SPF_CTX_T *spfctx, char *ip_address, size_t ip_address_len)
{
	if (spfctx == NULL)
		return EINVAL;

	if (ip_address == NULL)
		return EINVAL;

	/*
	 * we don't care at this point if it is ipv6 or ipv4
	 */
	(void) memset(spfctx->ip_address, '\0', sizeof spfctx->ip_address);
	(void) strlcpy(spfctx->ip_address, ip_address, sizeof spfctx->ip_address);
	return 0;
}

int
opendmarc_spf_specify_helo_domain(SPF_CTX_T *spfctx, char *helo_domain, size_t helo_domain_len)
{
	char copy[sizeof spfctx->mailfrom_addr];
	char *cp;
	char *ep;

	if (spfctx == NULL)
		return EINVAL;

	if (helo_domain == NULL)
		return 0;

	(void) memset(copy, '\0', sizeof copy);
	(void) strlcpy(copy, helo_domain, sizeof copy);
	cp = strrchr(copy, '<');
	if (cp == NULL)
		cp = copy;
	ep = strchr(cp, '>');
	if (ep != NULL)
		*ep = '\0';
	ep = strchr(cp, '@');
	if (ep != NULL)
		cp = ep+1;

	(void) memset(spfctx->helo_domain, '\0', sizeof spfctx->helo_domain);
	(void) strlcpy(spfctx->helo_domain, cp, sizeof spfctx->helo_domain);
	return 0;
}

int
opendmarc_spf_specify_mailfrom(SPF_CTX_T *spfctx, char *mailfrom, size_t mailfrom_len, int *use_flag)
{
	char copy[sizeof spfctx->mailfrom_addr];
	char *cp;
	char *ep;

	if (use_flag != NULL)
		*use_flag = FALSE;

	if (spfctx == NULL)
		return EINVAL;

	if (mailfrom == NULL)
		return EINVAL;
	
	(void) memset(copy, '\0', sizeof copy);
	(void) strlcpy(copy, mailfrom, sizeof copy);

	cp = strrchr(copy, '<');
	if (cp == NULL)
		cp = copy;
	else
		++cp;
	ep = strchr(cp, '>');
	if (ep != NULL)
		*ep = '\0';

	(void) memset(spfctx->mailfrom_addr, '\0', sizeof spfctx->mailfrom_addr);
	(void) strlcpy(spfctx->mailfrom_addr, cp, sizeof spfctx->mailfrom_addr);

	ep = strchr(cp, '@');
	if (ep != NULL)
	{
		cp = ep+1;
		if (use_flag != NULL)
			*use_flag = TRUE;
	}
		
	if (strcasecmp(cp, "MAILER_DAEMON") == 0)
		cp = "";

	(void) memset(spfctx->mailfrom_domain, '\0', sizeof spfctx->mailfrom_domain);
	(void) strlcpy(spfctx->mailfrom_domain, cp, sizeof spfctx->mailfrom_domain);
	return 0;
}

int
opendmarc_spf_specify_record(SPF_CTX_T *spfctx, char *spf_record, size_t spf_record_length)
{
	if (spfctx == NULL)
	{
		return EINVAL;
	}
	(void) memset(spfctx->spf_record, '\0', sizeof spfctx->spf_record);
	if (spf_record == NULL)
	{
		char *  spf_ret;
		int	reply;
		char	cname[256];
		char	spfbuf[BUFSIZ];

		/* look it up */
		spf_ret = opendmarc_spf_dns_get_record(spfctx->mailfrom_domain, &reply, spfbuf, sizeof spfbuf, cname, sizeof cname, TRUE);
		if (spf_ret == NULL)
		{
			switch(reply)
			{
			    case HOST_NOT_FOUND:
			    case NO_DATA:
				return DMARC_POLICY_SPF_OUTCOME_NONE;
				break;
			    case NO_RECOVERY:
			    case TRY_AGAIN:
				return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
				break;
			}
			return DMARC_POLICY_SPF_OUTCOME_NONE;
		}
		(void) strlcpy(spfctx->spf_record, spfbuf, sizeof spfctx->spf_record);
		return 0;
	}
	(void) strlcpy(spfctx->spf_record, spf_record, sizeof spfctx->spf_record);
	return 0;
}

int
opendmarc_spf_test(char *ip_address, char *mail_from_domain, char *helo_domain, char *spf_record, int softfail_okay_flag, char *human_readable, size_t human_readable_len, int *used_mfrom)
{
	SPF_CTX_T *	ctx;
	int		ret;
	int		len;
	char 		xbuf[BUFSIZ];

	if (used_mfrom != NULL)
		*used_mfrom = FALSE;

	(void) memset(xbuf, '\0', sizeof xbuf);
	ctx = opendmarc_spf_alloc_ctx();
	if (ctx == NULL)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, strerror(errno), human_readable_len);
		return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
	}

	if (ip_address == NULL)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, "No IP address available", human_readable_len);
		ctx = opendmarc_spf_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_FAIL;
	}

	if (mail_from_domain == NULL && helo_domain == NULL)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, "No Domain name available to check", human_readable_len);
		ctx = opendmarc_spf_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_FAIL;
	}

	ret = opendmarc_spf_specify_mailfrom(ctx, mail_from_domain, strlen(mail_from_domain), used_mfrom);
	if (ret != 0)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, strerror(errno), human_readable_len);
		ctx = opendmarc_spf_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
	}

	ret = opendmarc_spf_specify_helo_domain(ctx, helo_domain, strlen(helo_domain));
	if (ret != 0)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, strerror(errno), human_readable_len);
		ctx = opendmarc_spf_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
	}

	ret = opendmarc_spf_specify_ip_address(ctx, ip_address, strlen(ip_address));
	if (ret != 0)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, strerror(errno), human_readable_len);
		ctx = opendmarc_spf_free_ctx(ctx);
		return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
	}

	if (spf_record == NULL)
		len = 0;
	else
		len = strlen(spf_record);
	ret = opendmarc_spf_specify_record(ctx, spf_record, len);
	if (ret != 0)
	{
		if (human_readable != NULL)
			(void) strlcpy(human_readable, hstrerror(h_errno), human_readable_len);
		ctx = opendmarc_spf_free_ctx(ctx);
		return ret;
	}

	ret = opendmarc_spf_parse(ctx, 0, xbuf, sizeof xbuf);
	if (human_readable != NULL)
		(void) strlcpy(human_readable, opendmarc_spf_status_to_msg(ctx, ret), human_readable_len);
	ctx = opendmarc_spf_free_ctx(ctx);

	if (ret != SPF_RETURN_OK_PASSED)
	{
		switch (ret)
		{
		    case SPF_RETURN_UNDECIDED:
		    case SPF_RETURN_NEUTRAL:
		    case SPF_RETURN_SOFTFAIL:
			if (softfail_okay_flag == TRUE)
				return DMARC_POLICY_SPF_OUTCOME_PASS;
			else
				return DMARC_POLICY_SPF_OUTCOME_FAIL;
			break;
		    case SPF_RETURN_INTERNAL:
			return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
		}
		return DMARC_POLICY_SPF_OUTCOME_FAIL;
	}
	return DMARC_POLICY_SPF_OUTCOME_PASS;
}

#endif /* HAVE_SPF2_H */

#endif /* WITH_SPF */
