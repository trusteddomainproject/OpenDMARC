/***********************************************************************
** OPENDMARC_XML.C
**		OPENDMARC_XML -- Parse a blob of xml DMARC report data
**		OPENDMARC_XML_PARSE -- Read a file into a blob
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
************************************************************************/ 
#include "opendmarc_internal.h"


/***********************************************************************
** OPENDMARC_XML -- Parse a blob of xml DMARC report data
**	Arguments:
**		b	-- The blob of xml report data
**		blen	-- Size of blob
**		fname	-- If read from a file
**	Returns:
**		Nothing yet NEED TO DESIGN OUTPUT
**	Side Effects:
**		Pushes and pops off local stack, no recursion.
************************************************************************/ 
#define MAX_STACK_DEPTH		(10)
#define MAX_STACK_LINE_LEN	(256)
#define MAX_ITEM_NAME_LEN	(64)
typedef char STACK[MAX_STACK_DEPTH][MAX_STACK_LINE_LEN];

void
opendmarc_xml(char *b, size_t blen, char *fname)
{
	STACK stack;
	int    sidx = -1;
	char *cp, *ep, *sp;
	int i;
	int inside = FALSE;
	char org_name[MAX_ITEM_NAME_LEN];
	time_t t;
	struct tm *tm;
	char begin[MAX_ITEM_NAME_LEN];
	char end[MAX_ITEM_NAME_LEN];
	char source_ip[MAX_ITEM_NAME_LEN];
	char report_id[MAX_ITEM_NAME_LEN];
	int  count;
	char disposition[MAX_ITEM_NAME_LEN];
	char domain[MAX_ITEM_NAME_LEN];
	char type[MAX_ITEM_NAME_LEN];
	char adkim[8];
	char aspf[8];
	char p[32];
	char pct[8];
	char fromdomain[MAX_ITEM_NAME_LEN];
	char dd[MAX_ITEM_NAME_LEN];
	char dr[MAX_ITEM_NAME_LEN];
	char sd[MAX_ITEM_NAME_LEN];
	char sr[MAX_ITEM_NAME_LEN];

	(void) memset(stack, '\0', sizeof(STACK));
	(void) memset(source_ip, '\0', sizeof source_ip);
	(void) memset(disposition, '\0', sizeof disposition);
	(void) memset(fromdomain, '\0', sizeof fromdomain);
	(void) memset(dd, '\0', sizeof dd);
	(void) memset(dr, '\0', sizeof dr);
	(void) memset(sd, '\0', sizeof sd);
	(void) memset(sr, '\0', sizeof sr);
	count = 0;

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
			{
				if (sidx == -1)
				{
					//(void) fprintf(stderr, "%s: <%s>: %s\n", fname,
					//	cp, "End token with never a start token (ignored)");
					cp = sp;
					continue;
				}
				if (strcasecmp(cp+1, "record") == 0)
				{
					if (strlen(type) == 0)
						(void)strlcpy(type, "nil", sizeof type);
					printf("%s,%s,%s,policy=%s:%s:%s:%s,outcome=%d:%s:%s,dkim=%s:%s,spf=%s:%s,type=%s,from=%s\n",
							begin, org_name, domain, adkim, aspf, p, pct, count, source_ip, disposition,
							(*dd == '\0')? "nil" : dd, 
							(*dr == '\0')? "nil" : dr, 
							(*sd == '\0')? "nil" : sd, 
							(*sr == '\0')? "nil" : sr, 
							type, fromdomain);
					count = 0;
					(void) memset(source_ip, '\0', sizeof source_ip);
					(void) memset(disposition, '\0', sizeof disposition);
					(void) memset(type, '\0', sizeof type);
					(void) memset(fromdomain, '\0', sizeof fromdomain);
					(void) memset(dd, '\0', sizeof dd);
					(void) memset(dr, '\0', sizeof dr);
					(void) memset(sd, '\0', sizeof sd);
					(void) memset(sr, '\0', sizeof sr);
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
					if (sidx < 0)
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
					//(void) fprintf(stderr, "%s: <%s>: %s\n", fname,
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
					//(void) fprintf(stderr, "%s: <%s>: Too much depth (%d max) Aborted\n",
					//	fname, cp, MAX_STACK_DEPTH);
					return;
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
			else if (strcasecmp(stack[sidx], "begin") == 0)
			{
				t = strtoul(cp, NULL, 10);
				tm = gmtime(&t);
				(void) memset(begin, '\0', sizeof begin);
				(void) strftime(begin, sizeof begin, "%F %H:%M:%S", tm);
			}
			else if (strcasecmp(stack[sidx], "end") == 0)
			{
				t = strtoul(cp, NULL, 10);
				tm = gmtime(&t);
				(void) memset(end, '\0', sizeof end);
				(void) strftime(end, sizeof end, "%F", tm);
			}
			else if (strcasecmp(stack[sidx], "source_ip") == 0)
			{
				(void) strlcpy(source_ip, cp, sizeof source_ip);
			}
			else if (strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "domain") == 0)
			{
				(void) memset(domain, '\0', sizeof domain);
				(void) strlcpy(domain, cp, sizeof domain);
			}
			else if (strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "adkim") == 0)
			{
				(void) memset(adkim, '\0', sizeof adkim);
				(void) strlcpy(adkim, cp, sizeof adkim);
			}
			else if (strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "aspf") == 0)
			{
				(void) memset(aspf, '\0', sizeof aspf);
				(void) strlcpy(aspf, cp, sizeof aspf);
			}
			else if (strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "pct") == 0)
			{
				(void) memset(pct, '\0', sizeof pct);
				(void) strlcpy(pct, cp, sizeof pct);
			}
			else if (strcasecmp(stack[sidx-1], "policy_published") == 0 &&
					strcasecmp(stack[sidx], "p") == 0)
			{
				(void) memset(p, '\0', sizeof p);
				(void) strlcpy(p, cp, sizeof p);
			}
			else if (strcasecmp(stack[sidx], "type") == 0)
			{
				if (strlen(type) > 0)
					(void) strlcat(type, " ", sizeof type);
				(void) strlcat(type, cp, sizeof type);
			}
			else if (strcasecmp(stack[sidx], "header_from") == 0)
			{
				(void) strlcpy(fromdomain, cp, sizeof fromdomain);
			}
			else if (strcasecmp(stack[sidx-1], "dkim") == 0 &&
				(strcasecmp(stack[sidx], "domain") == 0))
			{
				if (strlen(dd) > 0)
					(void) strlcat(dd, " ", sizeof dd);
				if (strlen(cp) == 0)
					cp = "nil";
				(void) strlcat(dd, cp, sizeof dd);
			}
			else if (strcasecmp(stack[sidx-1], "dkim") == 0 &&
				(strcasecmp(stack[sidx], "result") == 0))
			{
				if (strlen(dr) > 0)
					(void) strlcat(dr, " ", sizeof dr);
				if (strlen(cp) == 0)
					cp = "nil";
				(void) strlcat(dr, cp, sizeof dr);
			}
			else if (strcasecmp(stack[sidx-1], "spf") == 0 &&
				(strcasecmp(stack[sidx], "domain") == 0))
			{
				if (strlen(sd) > 0)
					(void) strlcat(sd, " ", sizeof sd);
				if (strlen(cp) == 0)
					cp = "nil";
				(void) strlcat(sd, cp, sizeof sd);
			}
			else if (strcasecmp(stack[sidx-1], "spf") == 0 &&
				(strcasecmp(stack[sidx], "result") == 0))
			{
				if (strlen(sr) > 0)
					(void) strlcat(sr, " ", sizeof sr);
				if (strlen(cp) == 0)
					cp = "nil";
				(void) strlcat(sr, cp, sizeof sr);
			}
			else if (strcasecmp(stack[sidx], "count") == 0)
			{
				count = strtoul(cp, NULL, 10);
			}
			else if (strcasecmp(stack[sidx], "disposition") == 0)
			{
				(void) strlcpy(disposition, cp, sizeof disposition);
			}
			*sp = '<';
			cp = sp-1;
			inside = FALSE;
			continue;
		}
	}
}

void
opendmarc_xml_parse(char *fname)
{
	struct stat statb;
	FILE *fp;
	char *bufp;
	int   ret;

	ret = lstat(fname, &statb);
	if (ret != 0)
	{
		//(void) fprintf(stderr, "%s: %s\n", fname, strerror(errno));
		return;
	}
	if (statb.st_size == 0)
	{
		//(void) fprintf(stderr, "%s: %s\n", fname, "Empty file.");
		return;
	}

	bufp = calloc(statb.st_size, 1);
	if (bufp == NULL)
	{
		//(void) fprintf(stderr, "%s: %s\n", fname, strerror(errno));
		return;
	}

	fp = fopen(fname, "r");
	if (fp == NULL)
	{
		//(void) fprintf(stderr, "%s: %s\n", fname, strerror(errno));
		(void) free(bufp);
		return;
	}

	(void) fread(bufp, 1, statb.st_size, fp);
	if (ferror(fp))
	{
		//(void) fprintf(stderr, "%s: %s\n", fname, strerror(errno));
		(void) free(bufp);
		(void) fclose(fp);
		return;
	}
	(void) fclose(fp);
	(void) opendmarc_xml(bufp, statb.st_size, fname);
	(void) free(bufp);
	return;
}

#ifdef LIBOPENDMARC_XML_MAIN
int
main(int argc, char **argv)
{
	int c;
	while ((c = getopt(argc, argv, "")) != -1)
	{
		switch(c)
		{
		    default:
		    case '?':
usage:			
			printf("Usage: dmarcreport file(s).xml\n");
			return 0;
		}
	}
	if (optind == argc)
		goto usage;
	for (; optind < argc; ++optind)
		opendmarc_xml_parse(argv[optind]);
	return 0;
}
#endif /* LIBOPENDMARC_XML_MAIN */
