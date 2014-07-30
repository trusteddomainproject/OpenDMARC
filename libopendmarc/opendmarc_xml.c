/***********************************************************************
** OPENDMARC_XML.C
**		OPENDMARC_XML -- Parse a blob of xml DMARC report data
**		OPENDMARC_XML_PARSE -- Read a file into a blob
**  Copyright (c) 2012-2014, The Trusted Domain Project.  All rights reserved.
************************************************************************/ 
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

static char *Taglist[] = {
	"adkim",
	"aspf",
	"auth_results",
	"begin",
	"comment",
	"count",
	"date_range",
	"disposition",
	"dkim",
	"domain",
	"email",
	"end",
	"extra_contact_info",
	"feedback",
	"header_from",
	"human_result",
	"identifiers",
	"org_name",
	"p",
	"pct",
	"policy_evaluated",
	"policy_published",
	"reason",
	"record",
	"report_id",
	"report_metadata",
	"result",
	"row",
	"source_ip",
	"sp",
	"spf",
	"type",
	NULL,
};

static int
tag_lookup(char *tag)
{
	char **cpp;

	for (cpp = Taglist; *cpp != NULL; ++cpp)
	{
		if (strcasecmp(*cpp, tag) == 0)
			return TRUE;
	}
	return FALSE;
}

/***********************************************************************
** OPENDMARC_XML -- Parse a blob of xml DMARC report data
**	Arguments:
**		b	-- The blob of xml report data
**		blen	-- Size of blob
**	Returns:
**		Nothing yet NEED TO DESIGN OUTPUT
**	Side Effects:
**		Pushes and pops off local stack, no recursion.
************************************************************************/ 
# define MAX_STACK_DEPTH		(10)
# define MAX_STACK_LINE_LEN	(256)
# define MAX_ITEM_NAME_LEN	(256)
typedef char STACK[MAX_STACK_DEPTH][MAX_STACK_LINE_LEN];

u_char **
opendmarc_xml(char *b, size_t blen, char *e, size_t elen)
{
	STACK		stack;
	int		sidx			 = -1;
	char		*cp, *ep, *sp, *tagp;
	int		i;
	int		inside = FALSE;
	char		org_name[MAX_ITEM_NAME_LEN];
	u_char **	ary			= NULL;
	int		ary_cnt			= 0;
	char		begin[MAX_ITEM_NAME_LEN];
	char		end[MAX_ITEM_NAME_LEN];
	char		source_ip[MAX_ITEM_NAME_LEN];
	char		report_id[MAX_ITEM_NAME_LEN];
	char		email[MAX_ITEM_NAME_LEN];
	char		count[MAX_ITEM_NAME_LEN];
	char		disposition[MAX_ITEM_NAME_LEN];
	char		policy_eval_dkim[MAX_ITEM_NAME_LEN];
	char		policy_eval_spf[MAX_ITEM_NAME_LEN];
	char		domain[MAX_ITEM_NAME_LEN];
	char		reason_type[MAX_ITEM_NAME_LEN];
	char		reason_comment[MAX_ITEM_NAME_LEN];
	char		adkim[8];
	char		aspf[8];
	char		p[32];
	char		pct[8];
	char		header_from[MAX_ITEM_NAME_LEN];
	char		auth_dkim_domain[MAX_ITEM_NAME_LEN];
	char		auth_dkim_result[MAX_ITEM_NAME_LEN];
	char		auth_dkim_human[MAX_ITEM_NAME_LEN];
	char		auth_spf_domain[MAX_ITEM_NAME_LEN];
	char		auth_spf_result[MAX_ITEM_NAME_LEN];
	char		auth_spf_human[MAX_ITEM_NAME_LEN];
	char		obuf[BUFSIZ * 2];
	char		e_buf[128];


	if (e == NULL)
	{
		e = e_buf;
		elen = sizeof e_buf;
	}
	(void) memset(auth_dkim_domain, '\0', sizeof auth_dkim_domain);
	(void) memset(auth_dkim_human,	'\0', sizeof auth_dkim_human);
	(void) memset(auth_dkim_result, '\0', sizeof auth_dkim_result);
	(void) memset(auth_spf_domain,	'\0', sizeof auth_spf_domain);
	(void) memset(auth_spf_human,	'\0', sizeof auth_spf_human);
	(void) memset(auth_spf_result,	'\0', sizeof auth_spf_result);
	(void) memset(count,		'\0', sizeof count);
	(void) memset(disposition,	'\0', sizeof disposition);
	(void) memset(email,		'\0', sizeof email);
	(void) memset(header_from,	'\0', sizeof header_from);
	(void) memset(policy_eval_dkim, '\0', sizeof policy_eval_dkim);
	(void) memset(policy_eval_spf,	'\0', sizeof policy_eval_spf);
	(void) memset(source_ip,	'\0', sizeof source_ip);
	(void) memset(stack, 		'\0', sizeof(STACK));

	(void) memset(obuf, '\0', sizeof obuf);
	(void) strlcpy(obuf, "begin,end,org_name,email,domain,adkim,aspf,p,pct,source_ip,count,disposition,policy_eval_dkim,policy_eval_spf,reason_type,reason_comment,header_from,auth_dkim_domain,auth_dkim_result,auth_dkim_human,auth_spf_domain,auth_spf_result,auth_spf_human", sizeof obuf);
	ary = opendmarc_util_pushargv((u_char *)obuf, ary, &ary_cnt);

	ep = b + blen;
	for (cp = b; cp < ep; ++cp)
	{
		if (isspace((int) *cp))
			continue;
			
		if (inside == FALSE)
		{
			if (*cp != '<')
				continue;
			++cp;
			for(sp = cp; *sp != '\0'; ++sp)
			{
				if (*sp == '?')
					break;
				if (isalpha((int) *sp) || *sp == '_' ||*sp == '/')
					continue;
				break;
			}
			if (*sp == '?')
				continue;
			*sp = '\0';
			if (*cp == '/')
				tagp = cp+1;
			else
				tagp = cp;
			if (tag_lookup(tagp) == FALSE)
			{
				continue;
			}
			if (*cp == '/')
			{
				if (sidx == -1)
				{
					//(void) fprintf(stderr, "<%s>: %s\n", 
					//	cp, "End token with never a start token (ignored)");
					cp = sp;
					continue;
				}
				if (strcasecmp(cp+1, "record") == 0)
				{
					(void) memset(obuf, '\0', sizeof obuf);
					(void) strlcat(obuf, begin, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, end, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, org_name, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, email, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, domain, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, adkim, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, aspf, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, p, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, pct, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, source_ip, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, count, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, disposition, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, policy_eval_dkim, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, policy_eval_spf, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, reason_type, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, reason_comment, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, header_from, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, auth_dkim_domain, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, auth_dkim_result, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, auth_dkim_human, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, auth_spf_domain, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, auth_spf_result, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					(void) strlcat(obuf, auth_spf_human, sizeof obuf);
					(void) strlcat(obuf, ",", sizeof obuf);
					ary = opendmarc_util_pushargv((u_char *)obuf, ary, &ary_cnt);
					if (ary == NULL)
					{
						int xerror = errno;

						(void) strlcpy(e, "Allocate memory :", elen);
						(void) strlcat(e, strerror(xerror), elen);
						return ary;
					}

					(void) memset(count,		'\0', sizeof count);
					(void) memset(source_ip,	'\0', sizeof source_ip);
					(void) memset(disposition,	'\0', sizeof disposition);
					(void) memset(policy_eval_dkim, '\0', sizeof policy_eval_dkim);
					(void) memset(policy_eval_spf,	'\0', sizeof policy_eval_spf);
					(void) memset(reason_type,	'\0', sizeof reason_type);
					(void) memset(reason_comment,	'\0', sizeof reason_comment);
					(void) memset(header_from,	'\0', sizeof header_from);
					(void) memset(auth_dkim_domain, '\0', sizeof auth_dkim_domain);
					(void) memset(auth_dkim_result, '\0', sizeof auth_dkim_result);
					(void) memset(auth_dkim_human,	'\0', sizeof auth_dkim_human);
					(void) memset(auth_spf_domain,	'\0', sizeof auth_spf_domain);
					(void) memset(auth_spf_result,	'\0', sizeof auth_spf_result);
					(void) memset(auth_spf_human,	'\0', sizeof auth_spf_human);
				}
				/*
				** If </foo> matches current <foo>, pop off the stack.
				** Possiblle bug here, for bad case of <foo>text</boo>
				** My understanding is that XML clauses may not overlap. That is,
				** the following is illegal:
				**     <aaa>text<bbb>text</aaa>text</bbb>
				*/
				if (strcasecmp(cp+1, stack[sidx]) == 0)
				{
					--sidx;
					cp = sp;
					if (sidx < -1)
						break;
					continue;
				}
				else
				{
					/* recover gracefully how? */
				}
				for (i = sidx; i > 0; --i)
				{
					if (strcasecmp(cp+1, stack[sidx]) == 0)
						break;
				}
				if (i < 0)
				{
					//(void) fprintf(stderr, "<%s>: %s\n",
					//	cp, "End token with no start token (ignored)");
					cp = sp;
					continue;
				}
				if (sidx >= 0)
					--sidx;
				cp = sp;
				continue;

			}
			else
			{
				++sidx;
				if (sidx >= MAX_STACK_DEPTH)
				{
					(void) strlcpy(e, "<", elen);
					(void) strlcat(e, cp, elen);
					(void) strlcat(e, ">: Too much stack depth", elen);
					return (ary = opendmarc_util_clearargv(ary));
				}
				(void) strlcpy(stack[sidx], cp, MAX_STACK_LINE_LEN);
				cp = sp;
				inside = TRUE;
				continue;
			}
		}
		else
		{
			if (*cp == '<')
			{
				inside = FALSE;
				--cp;
				continue;
			}
			for(sp = cp; *sp != '\0'; ++sp)
			{
				if (*sp == '<')
					break;
				continue;
			}
			if (*sp != '<')
			{
				cp = sp-1;
				continue;
			}
			*sp = '\0';
			if (strcasecmp(stack[sidx], "org_name") == 0)
			{
				(void) memset(org_name, '\0', sizeof org_name);
				(void) strlcpy(org_name, cp, sizeof org_name);
			}
			else if (strcasecmp(stack[sidx], "report_id") == 0)
			{
				(void) memset(report_id, '\0', sizeof report_id);
				(void) strlcpy(report_id, cp, sizeof report_id);
			}
			else if (strcasecmp(stack[sidx], "email") == 0)
			{
				(void) memset(email, '\0', sizeof email);
				(void) strlcpy(email, cp, sizeof email);
			}
			else if (strcasecmp(stack[sidx], "begin") == 0)
			{
				time_t t;
				struct tm *tm;

				t = strtoul(cp, NULL, 10);
				tm = gmtime(&t);
				(void) memset(begin, '\0', sizeof begin);
				(void) strftime(begin, sizeof begin, "%F-%H:%M:%S", tm);
			}
			else if (strcasecmp(stack[sidx], "end") == 0)
			{
				time_t t;
				struct tm *tm;

				t = strtoul(cp, NULL, 10);
				tm = gmtime(&t);
				(void) memset(end, '\0', sizeof end);
				(void) strftime(end, sizeof end, "%F-%H:%M:%S", tm);
			}
			else if (strcasecmp(stack[sidx], "source_ip") == 0)
			{
				(void) strlcpy(source_ip, cp, sizeof source_ip);
			}
			else if (sidx > 1 && strcasecmp(stack[sidx-2], "auth_results") == 0 &&
					strcasecmp(stack[sidx-1], "dkim") == 0 &&
					strcasecmp(stack[sidx], "domain") == 0)
			{
				if (*auth_dkim_domain == '\0')
					(void) strlcpy(auth_dkim_domain, cp, sizeof auth_dkim_domain);
				else
				{
					(void) strlcat(auth_dkim_domain, "|", sizeof auth_dkim_domain);
					(void) strlcat(auth_dkim_domain, cp, sizeof auth_dkim_domain);
				}
			}
			else if (sidx > 1 && strcasecmp(stack[sidx-2], "auth_results") == 0 &&
					strcasecmp(stack[sidx-1], "dkim") == 0 &&
					strcasecmp(stack[sidx], "result") == 0)
			{
				if (*auth_dkim_result == '\0')
					(void) strlcpy(auth_dkim_result, cp, sizeof auth_dkim_result);
				else
				{
					(void) strlcat(auth_dkim_result, "|", sizeof auth_dkim_result);
					(void) strlcat(auth_dkim_result, cp, sizeof auth_dkim_result);
				}
			}
			else if (sidx > 1 && strcasecmp(stack[sidx-2], "auth_results") == 0 &&
					strcasecmp(stack[sidx-1], "dkim") == 0 &&
					strcasecmp(stack[sidx], "human_result") == 0)
			{
				if (*auth_dkim_human == '\0')
					(void) strlcpy(auth_dkim_human, cp, sizeof auth_dkim_human);
				else
				{
					(void) strlcat(auth_dkim_human, "|", sizeof auth_dkim_human);
					(void) strlcat(auth_dkim_human, cp, sizeof auth_dkim_human);
				}
			}
			else if (sidx > 1 && strcasecmp(stack[sidx-2], "auth_results") == 0 &&
					strcasecmp(stack[sidx-1], "spf") == 0 &&
					strcasecmp(stack[sidx], "domain") == 0)
			{
				if (*auth_spf_domain == '\0')
					(void) strlcpy(auth_spf_domain, cp, sizeof auth_spf_domain);
				else
				{
					(void) strlcat(auth_spf_domain, "|", sizeof auth_spf_domain);
					(void) strlcat(auth_spf_domain, cp, sizeof auth_spf_domain);
				}
			}
			else if (sidx > 1 && strcasecmp(stack[sidx-2], "auth_results") == 0 &&
					strcasecmp(stack[sidx-1], "spf") == 0 &&
					strcasecmp(stack[sidx], "result") == 0)
			{
				if (*auth_spf_result == '\0')
					(void) strlcpy(auth_spf_result, cp, sizeof auth_spf_result);
				else
				{
					(void) strlcat(auth_spf_result, "|", sizeof auth_spf_result);
					(void) strlcat(auth_spf_result, cp, sizeof auth_spf_result);
				}
			}
			else if (sidx > 1 && strcasecmp(stack[sidx-2], "auth_results") == 0 &&
					strcasecmp(stack[sidx-1], "spf") == 0 &&
					strcasecmp(stack[sidx], "human_result") == 0)
			{
				if (*auth_spf_human == '\0')
					(void) strlcpy(auth_spf_human, cp, sizeof auth_spf_human);
				else
				{
					(void) strlcat(auth_spf_human, "|", sizeof auth_spf_human);
					(void) strlcat(auth_spf_human, cp, sizeof auth_spf_human);
				}
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "domain") == 0)
			{
				(void) memset(domain, '\0', sizeof domain);
				(void) strlcpy(domain, cp, sizeof domain);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "adkim") == 0)
			{
				(void) memset(adkim, '\0', sizeof adkim);
				(void) strlcpy(adkim, cp, sizeof adkim);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "aspf") == 0)
			{
				(void) memset(aspf, '\0', sizeof aspf);
				(void) strlcpy(aspf, cp, sizeof aspf);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "pct") == 0)
			{
				(void) memset(pct, '\0', sizeof pct);
				(void) strlcpy(pct, cp, sizeof pct);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "p") == 0)
			{
				(void) memset(p, '\0', sizeof p);
				(void) strlcpy(p, cp, sizeof p);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "reason") == 0 &&
					strcasecmp(stack[sidx], "type") == 0)
			{
				if (strlen(reason_type) > 0)
					(void) strlcat(reason_type, " ", sizeof reason_type);
				(void) strlcat(reason_type, cp, sizeof reason_type);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "reason") == 0 &&
					strcasecmp(stack[sidx], "comment") == 0)
			{
				if (strlen(reason_comment) > 0)
					(void) strlcat(reason_comment, " ", sizeof reason_comment);
				(void) strlcat(reason_comment, cp, sizeof reason_comment);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "identifiers") == 0 &&
				 strcasecmp(stack[sidx], "header_from") == 0)
			{
				/*
				 * Some sites put a full address in here.
				 * Some others list mutilple address here.
				 */
				if (*header_from == '\0')
					(void) strlcpy(header_from, cp, sizeof header_from);
				else
				{
					(void) strlcat(header_from, "|", sizeof header_from);
					(void) strlcat(header_from, cp, sizeof header_from);
				}
			}
			else if (strcasecmp(stack[sidx], "count") == 0)
			{
				(void) strlcpy(count, cp, sizeof count);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_evaluated") == 0 &&
					strcasecmp(stack[sidx], "disposition") == 0)
			{
				(void) strlcpy(disposition, cp, sizeof disposition);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_evaluated") == 0 &&
					strcasecmp(stack[sidx], "dkim") == 0)
			{
				(void) strlcpy(policy_eval_dkim, cp, sizeof policy_eval_dkim);
			}
			else if (sidx > 0 && strcasecmp(stack[sidx-1], "policy_evaluated") == 0 &&
					strcasecmp(stack[sidx], "spf") == 0)
			{
				(void) strlcpy(policy_eval_spf, cp, sizeof policy_eval_spf);
			}
			*sp = '<';
			cp = sp-1;
			inside = FALSE;
			continue;
		}
	}
	return ary;
}

u_char **
opendmarc_xml_parse(char *fname, char *err_buf, size_t err_len)
{
	struct stat	statb;
	FILE *		fp;
	char *		bufp;
	char		e_buf[128];
	int		ret;
	u_char **	ary = NULL;
	int		xerror;
	size_t		rb;

	if (fname == NULL)
	{
		xerror = errno;
		(void) snprintf(err_buf, err_len, "%s: %s", fname, "File name was NULL");
		errno = EINVAL;
		return NULL;
	}
	if (err_buf == NULL)
	{
		err_buf = e_buf;
		err_len = sizeof e_buf;
	}

	ret = lstat(fname, &statb);
	if (ret != 0)
	{
		xerror = errno;
		(void) snprintf(err_buf, err_len, "%s: %s", fname, strerror(errno));
		errno = xerror; 
		return NULL;
	}
	if (statb.st_size == 0)
	{
		xerror = errno;
		(void) snprintf(err_buf, err_len, "%s: %s", fname, "Empty file.");
		errno = xerror; 
		return NULL;
	}

	bufp = calloc(statb.st_size, 1);
	if (bufp == NULL)
	{
		xerror = errno;
		(void) snprintf(err_buf, err_len, "%s: %s", fname, strerror(errno));
		errno = xerror; 
		return NULL;
	}

	fp = fopen(fname, "r");
	if (fp == NULL)
	{
		xerror = errno;
		(void) snprintf(err_buf, err_len, "%s: %s", fname, strerror(errno));
		(void) free(bufp);
		errno = xerror;
		return NULL;
	}

	rb = fread(bufp, 1, statb.st_size, fp);
	if (rb != statb.st_size)
	{
		xerror = errno;
		(void) snprintf(err_buf, err_len, "%s: truncated read", fname);
		(void) free(bufp);
		(void) fclose(fp);
		errno = xerror;
		return NULL;
	}
	else if (ferror(fp))
	{
		xerror = errno;
		(void) snprintf(err_buf, err_len, "%s: %s", fname, strerror(errno));
		(void) free(bufp);
		(void) fclose(fp);
		errno = xerror;
		return NULL;
	}
	(void) fclose(fp);
	ary =  opendmarc_xml(bufp, statb.st_size, err_buf, err_len);
	xerror = errno;
	(void) free(bufp);
	errno = xerror;
	return ary;
}

