/*
**  Copyright (c) 2012-2017, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS
#endif /* ! _POSIX_PTHREAD_SEMANTICS */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>
#ifdef __linux__
# include <sys/prctl.h>
#endif /* __linux__ */
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif /* HAVE_PATHS_H */
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sysexits.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <syslog.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
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

/* libmilter */
#include <libmilter/mfapi.h>

/* libopendmarc */
#include <dmarc.h>

/* opendmarc includes */
#include "opendmarc.h"
#include "config.h"
#include "parse.h"
#include "test.h"
#include "util.h"
#include "opendmarc-ar.h"
#include "opendmarc-config.h"
#include "opendmarc-dstring.h"

/* macros */
#define	CMDLINEOPTS	"Ac:flnp:P:t:u:vV"
#define	DEFTIMEOUT	5
#define	MAXSPFRESULT	16
#define	RECEIVEDSPF	"Received-SPF"

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL	"/dev/null"
#endif /* ! _PATH_DEVNULL */
#ifndef _PATH_SENDMAIL
# define _PATH_SENDMAIL	"/usr/sbin/sendmail"
#endif /* ! _PATH_SENDMAIL */

#define	TRYFREE(x)	do { \
				if ((x) != NULL) \
				{ \
					free(x); \
					(x) = NULL; \
				} \
			} while (0)

/* data types */
/* DMARCF_HEADER -- a linked list of header fields */
struct dmarcf_header
{
	char *			hdr_name;
	char *			hdr_value;
	struct dmarcf_header *	hdr_next;
	struct dmarcf_header *	hdr_prev;
};

/* DMARCF_MSGCTX -- message-specific context */
struct dmarcf_msgctx
{
	int			mctx_spfresult;
	char *			mctx_jobid;
	struct dmarcf_header *	mctx_hqhead;
	struct dmarcf_header *	mctx_hqtail;
	struct dmarcf_dstring *	mctx_histbuf;
	struct dmarcf_dstring *	mctx_afrf;
	unsigned char		mctx_envfrom[BUFRSZ + 1];
	unsigned char		mctx_envdomain[BUFRSZ + 1];
	unsigned char		mctx_fromdomain[BUFRSZ + 1];
};
typedef struct dmarcf_msgctx * DMARCF_MSGCTX;

/* DMARCF_CONNCTX -- connection-specific context */
struct dmarcf_connctx
{
	_Bool			cctx_milterv2;
	DMARCF_MSGCTX		cctx_msg;
	DMARC_POLICY_T *	cctx_dmarc;
	struct dmarcf_config *	cctx_config;
	struct sockaddr_storage	cctx_ip;
	char			cctx_ipstr[BUFRSZ + 1];
	char			cctx_host[MAXHOSTNAMELEN + 1];
#if WITH_SPF
	char			cctx_helo[MAXHOSTNAMELEN + 1];
	char			cctx_rawmfrom[BUFRSZ + 1];
#endif
};
typedef struct dmarcf_connctx * DMARCF_CONNCTX;

/* DMARCF_CONFIG -- configuration object */
struct dmarcf_config
{
	_Bool			conf_reqhdrs;
	_Bool			conf_afrf;
	_Bool			conf_afrfnone;
	_Bool			conf_rejectfail;
	_Bool			conf_dolog;
	_Bool			conf_enablecores;
	_Bool			conf_addswhdr;
	_Bool			conf_authservidwithjobid;
	_Bool			conf_recordall;
#if WITH_SPF
	_Bool			conf_spfignoreresults;
	_Bool			conf_spfselfvalidate;
#endif /* WITH_SPF */
	_Bool			conf_ignoreauthclients;
	unsigned int		conf_refcnt;
	unsigned int		conf_dnstimeout;
	struct config *		conf_data;
	char *			conf_afrfas;
	char *			conf_afrfbcc;
	char *			conf_copyfailsto;
	char *			conf_reportcmd;
	char *			conf_authservid;
	char *			conf_historyfile;
	char *			conf_pslist;
	char *			conf_ignorelist;
	char **			conf_trustedauthservids;
	char **			conf_ignoredomains;
};

/* LIST -- basic linked list of strings */
struct list
{
	char *		list_str;
	struct list *	list_next;
};

/* LOOKUP -- lookup table */
struct lookup
{
	char *		str;
	int		code;
};

/* table of syslog facilities mapped to names */
struct lookup log_facilities[] =
{
	{ "auth",		LOG_AUTH },
	{ "cron",		LOG_CRON },
	{ "daemon",		LOG_DAEMON },
	{ "kern",		LOG_KERN },
	{ "lpr",		LOG_LPR },
	{ "mail",		LOG_MAIL },
	{ "news",		LOG_NEWS },
	{ "security",		LOG_AUTH },       /* DEPRECATED */
	{ "syslog",		LOG_SYSLOG },
	{ "user",		LOG_USER },
	{ "uucp",		LOG_UUCP },
	{ "local0",		LOG_LOCAL0 },
	{ "local1",		LOG_LOCAL1 },
	{ "local2",		LOG_LOCAL2 },
	{ "local3",		LOG_LOCAL3 },
	{ "local4",		LOG_LOCAL4 },
	{ "local5",		LOG_LOCAL5 },
	{ "local6",		LOG_LOCAL6 },
	{ "local7",		LOG_LOCAL7 },
	{ NULL,			-1 }
};

/* prototypes */
sfsistat mlfi_abort __P((SMFICTX *));
sfsistat mlfi_close __P((SMFICTX *));
sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
#if WITH_SPF
sfsistat mlfi_helo __P((SMFICTX *, char *));
#endif
sfsistat mlfi_envfrom __P((SMFICTX *, char **));
sfsistat mlfi_eom __P((SMFICTX *));
sfsistat mlfi_header __P((SMFICTX *, char *, char *));
sfsistat mlfi_negotiate __P((SMFICTX *, unsigned long, unsigned long,
                                        unsigned long, unsigned long,
                                        unsigned long *, unsigned long *,
                                        unsigned long *, unsigned long *));

static void dmarcf_config_free __P((struct dmarcf_config *));
static struct dmarcf_config *dmarcf_config_new __P((void));
sfsistat dmarcf_insheader __P((SMFICTX *, int, char *, char *));
sfsistat dmarcf_setreply __P((SMFICTX *, char *, char *, char *));

/* globals */
_Bool dolog;
_Bool die;
_Bool reload;
_Bool no_i_whine;
_Bool testmode;
int diesig;
struct dmarcf_config *curconf;
struct list *ignore;
char *progname;
char *conffile;
char *sock;
char *myname;
char myhostname[MAXHOSTNAMELEN + 1];
pthread_mutex_t conf_lock;

/*
**  DMARCF_ADDRCPT -- wrapper for smfi_addrcpt()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	addr -- address to add
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dmarcf_addrcpt(SMFICTX *ctx, char *addr)
{
	assert(ctx != NULL);

	if (testmode)
		return dmarcf_test_addrcpt(ctx, addr);
	else
		return smfi_addrcpt(ctx, addr);
}

/*
**  DMARCF_SETREPLY -- wrapper for smfi_setreply()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	rcode -- SMTP reply code
**  	xcode -- SMTP enhanced status code
**  	replytxt -- reply text
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dmarcf_setreply(SMFICTX *ctx, char *rcode, char *xcode, char *replytxt)
{
	assert(ctx != NULL);

	if (testmode)
		return dmarcf_test_setreply(ctx, rcode, xcode, replytxt);
	else
		return smfi_setreply(ctx, rcode, xcode, replytxt);
}

/*
**  DMARCF_INSHEADER -- wrapper for smfi_insheader()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	idx -- index at which to insert
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dmarcf_insheader(SMFICTX *ctx, int idx, char *hname, char *hvalue)
{
	assert(ctx != NULL);
	assert(hname != NULL);
	assert(hvalue != NULL);

	if (testmode)
		return dmarcf_test_insheader(ctx, idx, hname, hvalue);
	else
#ifdef HAVE_SMFI_INSHEADER
		return smfi_insheader(ctx, idx, hname, hvalue);
#else /* HAVE_SMFI_INSHEADER */
		return smfi_addheader(ctx, hname, hvalue);
#endif /* HAVE_SMFI_INSHEADER */
}

/*
**  DMARCF_GETPRIV -- wrapper for smfi_getpriv()
**
**  Parameters:
**  	ctx -- milter (or test) context
**
**  Return value:
**  	The stored private pointer, or NULL.
*/

void *
dmarcf_getpriv(SMFICTX *ctx)
{
	assert(ctx != NULL);

	if (testmode)
		return dmarcf_test_getpriv((void *) ctx);
	else
		return smfi_getpriv(ctx);
}

/*
**  DMARCF_SETPRIV -- wrapper for smfi_setpriv()
**
**  Parameters:
**  	ctx -- milter (or test) context
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dmarcf_setpriv(SMFICTX *ctx, void *ptr)
{
	assert(ctx != NULL);

	if (testmode)
		return dmarcf_test_setpriv((void *) ctx, ptr);
	else
		return smfi_setpriv(ctx, ptr);
}

/*
**  DMARCF_GETSYMVAL -- wrapper for smfi_getsymval()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	sym -- symbol to retrieve
**
**  Return value:
**  	Pointer to the value of the requested MTA symbol.
*/

char *
dmarcf_getsymval(SMFICTX *ctx, char *sym)
{
	assert(ctx != NULL);
	assert(sym != NULL);

	if (testmode)
		return dmarcf_test_getsymval(ctx, sym);
	else
		return smfi_getsymval(ctx, sym);
}

/*
**  DMARCF_PARSE_RECEIVED_SPF -- try to extract a result from a Received-SPF
**                               header field
**
**  Parameters:
**  	str -- the value of the Received-SPF field to analyze
**  	
**  Return value:
**  	A ARES_RESULT_* constant.
*/

int
dmarcf_parse_received_spf(char *str)
{
	_Bool copying = FALSE;
	_Bool escaped = FALSE;
	int parens = 0;
	char *p;
	char *r;
	char *end;
	char result[MAXSPFRESULT + 1];

	assert(str != NULL);

	memset(result, '\0', sizeof result);
	r = result;
	end = &result[sizeof result - 1];

	for (p = str; *p != '\0'; p++)
	{
		if (escaped)
		{
			if (copying)
			{
				if (r < end)
					*r++ = *p;
			}

			escaped = FALSE;
		}
		else if (copying)
		{
			if (!escaped && *p == '\\')
			{
				escaped = TRUE;
			}
			else if (*p == '(')
			{
				copying = FALSE;
				parens++;
			}
 			else if (isascii(*p) && isspace(*p))
			{
				copying = FALSE;
			}
			else if (r < end)
			{
				*r++ = *p;
			}
		}
		else if (*p == '(')
		{
			parens++;
		}
		else if (*p == ')' && parens > 0)
		{
			parens--;
		}
		else if (parens == 0)
		{
			if (isascii(*p) && isspace(*p))
				continue;

			if (!copying)
			{
				if (result[0] != '\0')
					break;

				copying = TRUE;
				if (r < end)
					*r++ = *p;
			}
		}
	}

	if (strcasecmp(result, "pass") == 0)
		return ARES_RESULT_PASS;
	else if (strcasecmp(result, "fail") == 0)
		return ARES_RESULT_FAIL;
	else if (strcasecmp(result, "softfail") == 0)
		return ARES_RESULT_SOFTFAIL;
	else if (strcasecmp(result, "neutral") == 0)
		return ARES_RESULT_NEUTRAL;
	else if (strcasecmp(result, "temperror") == 0)
		return ARES_RESULT_TEMPERROR;
	else if (strcasecmp(result, "none") == 0)
		return ARES_RESULT_NONE;
	else
		return ARES_RESULT_PERMERROR;
}

/*
**  DMARCF_ADDLIST -- add an entry to a singly-linked list
**
**  Parameters:
**  	str -- string to add
**  	head -- address of list head pointer (updated)
**
**  Return value:
**  	None.
*/

void
dmarcf_addlist(const char *str, struct list **head)
{
	struct list *new;

	assert(str != NULL);
	assert(head != NULL);

	new = malloc(sizeof(struct list));
	if (new != NULL)
	{
		new->list_next = *head;
		new->list_str = strdup(str);
		*head = new;
	}
}

/*
**  DMARCF_LOAD_DNSDATA -- load fake DNS data into the library
**
**  Parameters:
**  	path -- path to file to read
**
**  Return value:
**  	FALSE iff load wasn't possible; caller should check errno
*/

_Bool
dmarcf_load_dnsdata(char *path)
{
	_Bool gapfound;
	const char *key;
	const char *value;
	char *p;
	FILE *f;
	char buf[BUFRSZ];

	assert(path != NULL);

	f = fopen(path, "r");
	if (f == NULL)
		return FALSE;

	memset(buf, '\0', sizeof buf);

	while (fgets(buf, sizeof buf - 1, f) != NULL)
	{
		key = NULL;
		value = NULL;
		gapfound = FALSE;

		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n' || *p == '#')
			{
				*p = '\0';
				break;
			}
			else if (!isspace(*p))
			{
				if (key == NULL)
					key = p;
				else if (gapfound && value == NULL)
					value = p;
			}
			else
			{
				if (!gapfound)
				{
					*p = '\0';
					gapfound = TRUE;
				}
			}
		}

		opendmarc_dns_fake_record(key, value);
	}

	fclose(f);

	return TRUE;
}

/*
**  DMARCF_LOADLIST -- add a file's worth of entries to a singly-linked list
**
**  Parameters:
**  	path -- path to file to read
**  	head -- address of list head pointer (updated)
**
**  Return value:
**  	FALSE iff there was an error; caller should check errno.
*/

_Bool
dmarcf_loadlist(char *path, struct list **head)
{
	int spaces;
	int datalen;
	struct list *new;
	char *p;
	FILE *f;
	char buf[BUFRSZ + 1];

	assert(path != NULL);
	assert(head != NULL);

	f = fopen(path, "r");
	if (f == NULL)
		return FALSE;

	memset(buf, '\0', sizeof buf);

	while (fgets(buf, sizeof buf - 1, f) != NULL)
	{
		spaces = 0;
		datalen = 0;

		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n' || *p == '#')
			{
				*p = '\0';
				break;
			}
			else if (isspace(*p))
			{
				if (datalen > 0)
				{
					*p = '\0';
					break;
				}

				spaces++;
			}
			else
			{
				datalen++;
			}
		}

		if (datalen == 0)
			continue;

		if (spaces > 0)
			memmove(&buf[spaces], buf, datalen + 1);

		new = malloc(sizeof(struct list));
		if (new != NULL)
		{
			new->list_next = *head;
			new->list_str = strdup(buf);
			*head = new;
		}
	}

	fclose(f);

	return TRUE;
}

/*
**  DMARCF_FREELIST -- destroy a singly-linked list
**
**  Parameters:
**  	head -- list to free
**
**  Return value:
**  	None.
*/

void
dmarcf_freelist(struct list *head)
{
	struct list *cur;
	struct list *next;

	cur = head;
	while (cur != NULL)
	{
		free(cur->list_str);

		next = cur->list_next;

		free(cur);

		cur = next;
	}
}

/*
**  DMARCF_EATSPACES -- chomp spaces at the front and end of a string
**
**  Parameters:
**  	str -- string to crush
**
**  Return value:
**  	None.
*/

void
dmarcf_eatspaces(char *str)
{
	int content = 0;
	int spaces = 0;
	int len = 0;
	char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		len++;

		if (isascii(*p) && isspace(*p))
		{
			if (content == 0)
			{
				spaces++;
			}
			else
			{
				*p = '\0';
				break;
			}
		}
		else
		{
			content++;
		}
	}

	if (len != content)
		memmove(str, &str[spaces], content + 1);
}

/*
**  DMARCF_FREEARRAY -- destroy an array of strings
**
**  Parameters:
**  	a -- array to destroy
**
**  Return vaule:
** 	None.
*/

void
dmarcf_freearray(char **a)
{
	assert(a != NULL);

	free(a);
}

/*
**  DMARCF_MKARRAY -- convert a comma-separated string into an array
**
**  Parameters:
**  	str -- input string
**  	array -- output array
**
**  Return value:
**  	Array length, or -1 on error.
*/

int
dmarcf_mkarray(char *str, char ***array)
{
	int n = 0;
	int a = 0;
	int ns;
	char *p;
	char *ctx;
	char **out = NULL;

	for (p = strtok_r(str, ",", &ctx);
	     p != NULL;
	     p = strtok_r(NULL, ",", &ctx))
	{
		dmarcf_eatspaces(p);

		if (n + 1 >= a)
		{
			if (a == 0)
			{
				ns = 4;

				out = malloc(sizeof(char *) * ns);

				if (out == NULL)
					return -1;
			}
			else
			{
				char **new;

				ns = a * 2;

				new = realloc(out, sizeof(char *) * ns);
				if (new == NULL)
				{
					free(out);
					return -1;
				}

				out = new;
			}

			memset(&out[a], '\0', sizeof(char *) * (ns - a));

			a = ns;
		}

		out[n++] = p;
		out[n] = NULL;
	}

	*array = out;

	return n;
}

/*
**  DMARCF_MATCH -- match a string to an array
**
**  Parameters:
**  	str -- input string
**  	array -- input array
**  	icase -- ignore case?
**
**  Return value:
**  	TRUE iff "str" appears in "array".
*/

_Bool
dmarcf_match(const char *str, char **array, _Bool icase)
{
	int c;

	for (c = 0; array[c] != NULL; c++)
	{
		if ((!icase && strcmp(str, array[c]) == 0) ||
		    ( icase && strcasecmp(str, array[c]) == 0))
			return TRUE;
	}

	return FALSE;
}

/*
**  DMARCF_CHECKLIST -- search a linked list for an entry
**
**  Parameters:
**  	str -- string to find
**  	list -- list to search
**
**  Return value:
**  	TRUE iff "str" was found in "list"
*/

_Bool
dmarcf_checklist(const char *str, struct list *list)
{
	struct list *cur;

	assert(str != NULL);
	assert(list != NULL);

	for (cur = list; cur != NULL; cur = cur->list_next)
	{
		if (strcasecmp(str, cur->list_str) == 0)
			return TRUE;
	}

	return FALSE;
}

/*
**  DMARCF_CHECKHOST -- check a list for a hostname
**
**  Parameters:
**  	host -- hostname to find
**  	list -- list to search
**
**  Return value:
**  	TRUE if there's a match, FALSE otherwise.
*/

_Bool
dmarcf_checkhost(const char *host, struct list *list)
{
	const char *p;
	char buf[BUFRSZ + 1];

	assert(host != NULL);

	/* short circuit */
	if (list == NULL)
		return FALSE;

	/* iterate over the possibilities */
	for (p = host;
	     p != NULL;
	     p = (p == host ? strchr(host, '.') : strchr(p + 1, '.')))
	{
		snprintf(buf, sizeof buf, "!%s", p);

		/* try the negative case */
		if (dmarcf_checklist(buf, list))
			return FALSE;

		/* ...and now the positive case */
		if (dmarcf_checklist(&buf[1], list))
			return TRUE;
	}

	return FALSE;
}

/*
**  DMARCF_CHECKIP -- check a list an IP address or its matching wildcards
**
**  Parameters:
**  	ip -- IP address to find, as a _SOCK_ADDR
**  	list -- list to check
**
**  Return value:
**  	TRUE if there's a match, FALSE otherwise.
*/

_Bool
dmarcf_checkip(_SOCK_ADDR *ip, struct list *list)
{
	char ipbuf[MAXHOSTNAMELEN + 1];

	assert(ip != NULL);

	/* short circuit */
	if (list == NULL)
		return FALSE;

#if AF_INET6
	if (ip->sa_family == AF_INET6)
	{
		int bits;
		size_t dst_len;
		char *dst;
		struct sockaddr_in6 sin6;
		struct in6_addr addr;

		memcpy(&sin6, ip, sizeof sin6);

		memcpy(&addr, &sin6.sin6_addr, sizeof addr);

		memset(ipbuf, '\0', sizeof ipbuf);
		ipbuf[0] = '!';

		dst = &ipbuf[1];
		dst_len = sizeof ipbuf - 1;

		inet_ntop(AF_INET6, &addr, dst, dst_len);
		dmarcf_lowercase((u_char *) dst);

		if (dmarcf_checklist(ipbuf, list))
			return FALSE;

		if (dmarcf_checklist(&ipbuf[1], list))
			return TRUE;

		/* iterate over possible bitwise expressions */
		for (bits = 0; bits <= 128; bits++)
		{
			size_t sz;

			/* try this one */
			memset(ipbuf, '\0', sizeof ipbuf);
			ipbuf[0] = '!';

			dst = &ipbuf[1];
			dst_len = sizeof ipbuf - 1;

			inet_ntop(AF_INET6, &addr, dst, dst_len);
			dmarcf_lowercase((u_char *) dst);

			sz = strlcat(ipbuf, "/", sizeof ipbuf);
			if (sz >= sizeof ipbuf)
				return FALSE;

			dst = &ipbuf[sz];
			dst_len = sizeof ipbuf - sz;

			sz = snprintf(dst, dst_len, "%d", 128 - bits);
			if (sz >= sizeof ipbuf)
				return FALSE;

			if (dmarcf_checklist(ipbuf, list))
				return FALSE;

			if (dmarcf_checklist(&ipbuf[1], list))
				return TRUE;

			/* flip off a bit */
			if (bits != 128)
			{
				int idx;
				int bit;

				idx = 15 - (bits / 8);
				bit = bits % 8;
				addr.s6_addr[idx] &= ~(1 << bit);
			}
		}
	}
#endif /* AF_INET6 */

	if (ip->sa_family == AF_INET)
	{
		_Bool exists;
		int c;
		int bits;
		struct in_addr addr;
		struct in_addr mask;
		struct sockaddr_in sin;

		memcpy(&sin, ip, sizeof sin);
		memcpy(&addr.s_addr, &sin.sin_addr, sizeof addr.s_addr);

		/* try the IP address directly */
		exists = FALSE;

		ipbuf[0] = '!';
		(void) dmarcf_inet_ntoa(addr, &ipbuf[1], sizeof ipbuf - 1);

		if (dmarcf_checklist(ipbuf, list))
			return FALSE;

		if (dmarcf_checklist(&ipbuf[1], list))
			return TRUE;

		/* iterate over possible bitwise expressions */
		for (bits = 32; bits >= 0; bits--)
		{
			if (bits == 32)
			{
				mask.s_addr = 0xffffffff;
			}
			else
			{
				mask.s_addr = 0;
				for (c = 0; c < bits; c++)
					mask.s_addr |= htonl(1 << (31 - c));
			}

			addr.s_addr = addr.s_addr & mask.s_addr;

			memset(ipbuf, '\0', sizeof ipbuf);
			ipbuf[0] = '!';
			(void) dmarcf_inet_ntoa(addr, &ipbuf[1],
			                       sizeof ipbuf - 1);
			c = strlen(ipbuf);
			ipbuf[c] = '/';
			c++;

			snprintf(&ipbuf[c], sizeof ipbuf - c, "%d", bits);

			if (dmarcf_checklist(ipbuf, list))
				return FALSE;

			if (dmarcf_checklist(&ipbuf[1], list))
				return TRUE;

			(void) dmarcf_inet_ntoa(mask, &ipbuf[c],
			                        sizeof ipbuf - c);
		
			if (dmarcf_checklist(ipbuf, list))
				return FALSE;

			if (dmarcf_checklist(&ipbuf[1], list))
				return TRUE;
		}
	}

	return FALSE;
}

/*
**  DMARCF_INIT_SYSLOG -- initialize syslog()
**
**  Parameters:
**  	facility -- name of the syslog facility to use when logging;
**  	            can be NULL to request the default
**
**  Return value:
**  	None.
*/

static void
dmarcf_init_syslog(char *facility)
{
#ifdef LOG_MAIL
	int code;
	struct lookup *p = NULL;

	closelog();

	code = LOG_MAIL;
	if (facility != NULL)
	{
		for (p = log_facilities; p->str != NULL; p++)
		{
			if (strcasecmp(p->str, facility) == 0)
			{
				code = p->code;
				break;
			}
		}
	}

	openlog(progname, LOG_PID, code);
#else /* LOG_MAIL */
	closelog();

	openlog(progname, LOG_PID);
#endif /* LOG_MAIL */
}

/*
**  DMARCF_FINDHEADER -- find a header
**
**  Parameters:
**  	dfc -- filter context
**  	hname -- name of the header of interest
**  	instance -- which instance is wanted (0 = first)
**
**  Return value:
**  	Header field handle, or NULL if not found.
**
**  Notes:
**  	Negative values of "instance" search backwards from the end.
*/

static struct dmarcf_header *
dmarcf_findheader(DMARCF_MSGCTX dfc, char *hname, int instance)
{
	struct dmarcf_header *hdr;

	assert(dfc != NULL);
	assert(hname != NULL);

	if (instance < 0)
		hdr = dfc->mctx_hqtail;
	else
		hdr = dfc->mctx_hqhead;

	while (hdr != NULL)
	{
		if (strcasecmp(hdr->hdr_name, hname) == 0)
		{
			if (instance == 0 || instance == -1)
				return hdr;
			else if (instance > 0)
				instance--;
			else
				instance++;
		}

		if (instance < 0)
			hdr = hdr->hdr_prev;
		else
			hdr = hdr->hdr_next;
	}

	return NULL;
}

/*
**  DMARCF_CONFIG_LOAD -- load a configuration handle based on file content
**
**  Paramters:
**  	data -- configuration data loaded from config file
**  	conf -- configuration structure to load
**  	err -- where to write errors
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	0 -- success
**  	!0 -- error
**
**  Side effects:
**  	openlog() may be called by this function
*/

static int
dmarcf_config_load(struct config *data, struct dmarcf_config *conf,
                   char *err, size_t errlen)
{
	char *str;
	char confstr[BUFRSZ + 1];
	char basedir[MAXPATHLEN + 1];

	assert(conf != NULL);
	assert(err != NULL);

	memset(basedir, '\0', sizeof basedir);
	memset(confstr, '\0', sizeof confstr);

	if (data != NULL)
	{
		str = NULL;
		(void) config_get(data, "AuthservID", &str, sizeof str);
		if (str != NULL)
		{
			if (strcmp(str, "HOSTNAME") == 0)
				conf->conf_authservid = strdup(myhostname);
			else	
				conf->conf_authservid = strdup(str);
		}

		str = NULL;
		(void) config_get(data, "TrustedAuthservIDs", &str, sizeof str);
		if (str != NULL)
			dmarcf_mkarray(str, &conf->conf_trustedauthservids);

		str = NULL;
		(void) config_get(data, "IgnoreMailFrom", &str, sizeof str);
		if (str != NULL)
			dmarcf_mkarray(str, &conf->conf_ignoredomains);

		(void) config_get(data, "AuthservIDWithJobID",
		                  &conf->conf_authservidwithjobid,
		                  sizeof conf->conf_authservidwithjobid);

		memset(basedir, '\0', sizeof basedir);
		str = NULL;
		(void) config_get(data, "BaseDirectory", &str, sizeof str);
		if (str != NULL)
			strncpy(basedir, str, sizeof basedir - 1);

		(void) config_get(data, "CopyFailuresTo",
		                  &conf->conf_copyfailsto,
		                  sizeof conf->conf_copyfailsto);

		if (conf->conf_dnstimeout == DEFTIMEOUT)
		{
			(void) config_get(data, "DNSTimeout",
			                  &conf->conf_dnstimeout,
			                  sizeof conf->conf_dnstimeout);
		}

		(void) config_get(data, "EnableCoredumps",
		                  &conf->conf_enablecores,
		                  sizeof conf->conf_enablecores);

#if WITH_SPF
		(void) config_get(data, "SPFIgnoreResults",
		                  &conf->conf_spfignoreresults,
		                  sizeof conf->conf_spfignoreresults);

		(void) config_get(data, "SPFSelfValidate",
		                  &conf->conf_spfselfvalidate,
		                  sizeof conf->conf_spfselfvalidate);
#endif /* WITH_SPF */

		(void) config_get(data, "RejectFailures",
		                  &conf->conf_rejectfail,
		                  sizeof conf->conf_rejectfail);

		(void) config_get(data, "RequiredHeaders",
		                  &conf->conf_reqhdrs,
		                  sizeof conf->conf_reqhdrs);

		(void) config_get(data, "FailureReports",
		                  &conf->conf_afrf,
		                  sizeof conf->conf_afrf);

		(void) config_get(data, "FailureReportsOnNone",
		                  &conf->conf_afrfnone,
		                  sizeof conf->conf_afrfnone);

		(void) config_get(data, "FailureReportsSentBy",
		                  &conf->conf_afrfas,
		                  sizeof conf->conf_afrfas);

		(void) config_get(data, "FailureReportsBcc",
		                  &conf->conf_afrfbcc,
		                  sizeof conf->conf_afrfbcc);

		(void) config_get(data, "RecordAllMessages",
		                  &conf->conf_recordall,
		                  sizeof conf->conf_recordall);

		(void) config_get(data, "IgnoreAuthenticatedClients",
		                  &conf->conf_ignoreauthclients,
		                  sizeof conf->conf_ignoreauthclients);

		(void) config_get(data, "ReportCommand",
		                  &conf->conf_reportcmd,
		                  sizeof conf->conf_reportcmd);

		(void) config_get(data, "PublicSuffixList",
		                  &conf->conf_pslist,
		                  sizeof conf->conf_pslist);

		if (!conf->conf_dolog)
		{
			(void) config_get(data, "Syslog", &conf->conf_dolog,
			                  sizeof conf->conf_dolog);
		}

		if (!conf->conf_addswhdr)
		{
			(void) config_get(data, "SoftwareHeader",
			                  &conf->conf_addswhdr,
			                  sizeof conf->conf_addswhdr);
		}

		(void) config_get(data, "HistoryFile",
		                  &conf->conf_historyfile,
		                  sizeof conf->conf_historyfile);

		str = NULL;
		(void) config_get(data, "TestDNSData", &str, sizeof str);
		if (str != NULL)
		{
			if (!dmarcf_load_dnsdata(str))
			{
				snprintf(err, errlen,
				         "%s: can't load fake DNS data: %s",
				         str, strerror(errno));
				return -1;
			}
		}
	}

	if (conf->conf_trustedauthservids == NULL &&
	    conf->conf_authservid != NULL)
	{
		dmarcf_mkarray(conf->conf_authservid,
		               &conf->conf_trustedauthservids);
	}

	if (basedir[0] != '\0')
	{
		if (chdir(basedir) != 0)
		{
			snprintf(err, errlen, "%s: chdir(): %s",
			         basedir, strerror(errno));
			return -1;
		}
	}

	/* activate logging if requested */
	if (conf->conf_dolog)
	{
		char *log_facility = NULL;

		if (data != NULL)
		{
			(void) config_get(data, "SyslogFacility", &log_facility,
			                  sizeof log_facility);
		}

		dmarcf_init_syslog(log_facility);
	}

	return 0;
}

/*
**  DMARCF_CONFIG_RELOAD -- reload configuration if requested
**
**  Parameters:
**   	None.
**
**  Return value:
**  	None.
**
**  Side effects:
**  	If a reload was requested and is successful, "curconf" now points
**  	to a new configuration handle.
*/

static void
dmarcf_config_reload(void)
{
	struct dmarcf_config *new;
	char errbuf[BUFRSZ + 1];

	pthread_mutex_lock(&conf_lock);

	if (!reload)
	{
		pthread_mutex_unlock(&conf_lock);
		return;
	}

	if (conffile == NULL)
	{
		if (curconf->conf_dolog)
			syslog(LOG_ERR, "ignoring reload signal");

		reload = FALSE;

		pthread_mutex_unlock(&conf_lock);
		return;
	}

	new = dmarcf_config_new();
	if (new == NULL)
	{
		if (curconf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));
	}
	else
	{
		_Bool err = FALSE;
		u_int line;
		struct config *cfg;
		char *missing;
		char path[MAXPATHLEN + 1];

		memset(path, '\0', sizeof path);
		strncpy(path, conffile, sizeof path - 1);

		cfg = config_load(conffile, dmarcf_config, &line,
		                  path, sizeof path);

		if (cfg == NULL)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: configuration error at line %u: %s",
				        path, line, config_error());
			}
			dmarcf_config_free(new);
			err = TRUE;
		}

		if (!err)
		{
			missing = config_check(cfg, dmarcf_config);
			if (missing != NULL)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					        "%s: required parameter \"%s\" missing",
					        conffile, missing);
				}
				config_free(cfg);
				dmarcf_config_free(new);
				err = TRUE;
			}
		}

		if (!err && dmarcf_config_load(cfg, new, errbuf,
		                               sizeof errbuf) != 0)
		{
			if (curconf->conf_dolog)
				syslog(LOG_ERR, "%s: %s", conffile, errbuf);
			config_free(cfg);
			dmarcf_config_free(new);
			err = TRUE;
		}

		if (!err && new->conf_pslist != NULL)
		{
			if (opendmarc_tld_read_file(new->conf_pslist, "//",
			                            "*.", "!") != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "%s: read/parse error",
					       new->conf_pslist);
				}

				config_free(cfg);
				dmarcf_config_free(new);
				err = TRUE;
			}
		}
 
		if (!err)
		{
			if (curconf->conf_refcnt == 0)
				dmarcf_config_free(curconf);

			dolog = new->conf_dolog;
			curconf = new;
			new->conf_data = cfg;

			if (new->conf_dolog)
			{
				syslog(LOG_INFO,
				       "configuration reloaded from %s",
				       conffile);
			}
		}
	}

	reload = FALSE;

	pthread_mutex_unlock(&conf_lock);

	return;
}

/*
**  DMARCF_CLEANUP -- release local resources related to a message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	None.
*/

static void
dmarcf_cleanup(SMFICTX *ctx)
{
	DMARCF_MSGCTX dfc;
	DMARCF_CONNCTX cc;

	assert(ctx != NULL);

	cc = (DMARCF_CONNCTX) dmarcf_getpriv(ctx);

	if (cc == NULL)
		return;

	dfc = cc->cctx_msg;

	/* release memory, reset state */
	if (dfc != NULL)
	{
		if (dfc->mctx_histbuf != NULL)
			dmarcf_dstring_free(dfc->mctx_histbuf);
		if (dfc->mctx_afrf != NULL)
			dmarcf_dstring_free(dfc->mctx_afrf);

		if (dfc->mctx_hqhead != NULL)
		{
			struct dmarcf_header *hdr;
			struct dmarcf_header *prev;

			hdr = dfc->mctx_hqhead;
			while (hdr != NULL)
			{
				TRYFREE(hdr->hdr_name);
				TRYFREE(hdr->hdr_value);
				prev = hdr;
				hdr = hdr->hdr_next;
				TRYFREE(prev);
			}
		}

		free(dfc);
		cc->cctx_msg = NULL;
	}
}

#if SMFI_VERSION >= 0x01000000
/*
**  MLFI_NEGOTIATE -- handler called on new SMTP connection to negotiate
**                    MTA options
**
**  Parameters:
**  	ctx -- milter context
**	f0  -- actions offered by the MTA
**	f1  -- protocol steps offered by the MTA
**	f2  -- reserved for future extensions
**	f3  -- reserved for future extensions
**	pf0 -- actions requested by the milter
**	pf1 -- protocol steps requested by the milter
**	pf2 -- reserved for future extensions
**	pf3 -- reserved for future extensions
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_negotiate(SMFICTX *ctx,
	unsigned long f0, unsigned long f1,
	unsigned long f2, unsigned long f3,
	unsigned long *pf0, unsigned long *pf1,
	unsigned long *pf2, unsigned long *pf3)
{
	unsigned long reqactions = SMFIF_ADDHDRS|SMFIF_QUARANTINE;
	unsigned long wantactions = 0;
	unsigned long protosteps = (
#if !WITH_SPF
				    SMFIP_NOHELO |
#endif /* !WITH_SPF */
	                            SMFIP_NOUNKNOWN |
	                            SMFIP_NOBODY |
	                            SMFIP_NODATA |
	                            SMFIP_SKIP );
	DMARCF_CONNCTX cc;
	struct dmarcf_config *conf;

	dmarcf_config_reload();

	/* initialize connection context */
	cc = malloc(sizeof(struct dmarcf_connctx));
	if (cc == NULL)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "mlfi_negotiate(): malloc(): %s",
			       strerror(errno));
		}

		return SMFIS_TEMPFAIL;
	}

	memset(cc, '\0', sizeof(struct dmarcf_connctx));

	pthread_mutex_lock(&conf_lock);

	cc->cctx_config = curconf;
	curconf->conf_refcnt++;
	conf = curconf;

	pthread_mutex_unlock(&conf_lock);

	if (conf->conf_copyfailsto != NULL)
		reqactions |= SMFIF_ADDRCPT;

	/* verify the actions we need are available */
	if ((f0 & reqactions) != reqactions)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "mlfi_negotiate(): required milter action(s) not available (got 0x%lx, need 0x%lx)",
			       f0, reqactions);
		}

		pthread_mutex_lock(&conf_lock);
		conf->conf_refcnt--;
		pthread_mutex_unlock(&conf_lock);

		free(cc);

		return SMFIS_REJECT;
	}

	/* also try to get some nice features */
	wantactions = (wantactions & f0);

	/* set the actions we want */
	*pf0 = (reqactions | wantactions);

	/* disable as many protocol steps we don't need as are available */
	*pf1 = (protosteps & f1);
	*pf2 = 0;
	*pf3 = 0;

	/* set "milterv2" flag if SMFIP_SKIP was available */
	if ((f1 & SMFIP_SKIP) != 0)
		cc->cctx_milterv2 = TRUE;

	(void) dmarcf_setpriv(ctx, cc);

	return SMFIS_CONTINUE;
}
#endif /* SMFI_VERSION >= 0x01000000 */

/*
**  MLFI_CONNECT -- connection handler
**
**  Parameters:
**  	ctx -- milter context
**  	host -- hostname
**  	ip -- address, in in_addr form
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_connect(SMFICTX *ctx, char *host, _SOCK_ADDR *ip)
{
	DMARCF_CONNCTX cc;
	struct dmarcf_config *conf;

	dmarcf_config_reload();

	if (dmarcf_checkhost(host, ignore) ||
	    (ip != NULL && dmarcf_checkip(ip, ignore)))
	{
		if (curconf->conf_dolog)
			syslog(LOG_INFO, "ignoring connection from %s", host);
		return SMFIS_ACCEPT;
	}

	/* copy hostname and IP information to a connection context */
	cc = dmarcf_getpriv(ctx);
	if (cc == NULL)
	{
		cc = malloc(sizeof(struct dmarcf_connctx));
		if (cc == NULL)
		{
			pthread_mutex_lock(&conf_lock);

			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "%s malloc(): %s", host,
				       strerror(errno));
			}

			pthread_mutex_unlock(&conf_lock);

			return SMFIS_TEMPFAIL;
		}

		memset(cc, '\0', sizeof(struct dmarcf_connctx));

		pthread_mutex_lock(&conf_lock);

		cc->cctx_config = curconf;
		curconf->conf_refcnt++;

		conf = curconf;

		pthread_mutex_unlock(&conf_lock);

		dmarcf_setpriv(ctx, cc);
	}
	else
	{
		conf = cc->cctx_config;
	}

	if (host != NULL)
		strncpy(cc->cctx_host, host, sizeof cc->cctx_host - 1);

	if (ip == NULL)
	{
		struct sockaddr_in sa;

		memset(&sa, '\0', sizeof sa);
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		memcpy(&cc->cctx_ip, &sa, sizeof sa);
		(void) inet_ntop(AF_INET, &sa.sin_addr, cc->cctx_ipstr,
		                 sizeof cc->cctx_ipstr);
		cc->cctx_dmarc = opendmarc_policy_connect_init(cc->cctx_ipstr,
		                                               FALSE);
	}
	else if (ip->sa_family == AF_INET)
	{
		struct sockaddr_in sa;

		memcpy(&sa, ip, sizeof(struct sockaddr_in));
		(void) inet_ntop(AF_INET, &sa.sin_addr, cc->cctx_ipstr,
		                 sizeof cc->cctx_ipstr);
		cc->cctx_dmarc = opendmarc_policy_connect_init(cc->cctx_ipstr,
		                                               FALSE);

		memcpy(&cc->cctx_ip, ip, sizeof(struct sockaddr_in));
	}
#ifdef AF_INET6
	else if (ip->sa_family == AF_INET6)
	{
		struct sockaddr_in6 sa;

		memcpy(&sa, ip, sizeof(struct sockaddr_in6));
		(void) inet_ntop(AF_INET6, &sa.sin6_addr, cc->cctx_ipstr,
		                 sizeof cc->cctx_ipstr);
		cc->cctx_dmarc = opendmarc_policy_connect_init(cc->cctx_ipstr,
		                                               TRUE);

		memcpy(&cc->cctx_ip, ip, sizeof(struct sockaddr_in6));
	}
#endif /* AF_INET6 */

	if (cc->cctx_dmarc == NULL)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "%s: DMARC context initialization failed",
			       host);
		}
	}

	cc->cctx_msg = NULL;

	return SMFIS_CONTINUE;
}

#if WITH_SPF
/*
**  MLFI_HELO -- handler for HELO/EHLO command; only used for spf checks if configured.
**
**  Parameters:
**  	ctx -- milter context
**  	helo_domain -- possible helo domain
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_helo(SMFICTX *ctx, char *helo_domain)
{
	DMARCF_CONNCTX cc;
	struct dmarcf_config *conf;

	assert(ctx != NULL);

	cc = (DMARCF_CONNCTX) dmarcf_getpriv(ctx);
	if (cc != NULL)
	{
		conf = cc->cctx_config;
		if (!conf->conf_spfselfvalidate)
			return SMFIS_CONTINUE;

		if (helo_domain != NULL)
		{
			strncpy(cc->cctx_helo, helo_domain,
			        sizeof cc->cctx_helo - 1);
		}
	}
	return SMFIS_CONTINUE;
}
#endif /* WITH_SPF */

/*
**  MLFI_ENVFROM -- handler for MAIL FROM command; used to reset for a message
**
**  Parameters:
**  	ctx -- milter context
**  	envfrom -- array of arguments
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	DMARCF_MSGCTX dfc;
	DMARCF_CONNCTX cc;
	struct dmarcf_config *conf;

	assert(ctx != NULL);

	cc = (DMARCF_CONNCTX) dmarcf_getpriv(ctx);
	assert(cc != NULL);
	conf = cc->cctx_config;

	if (cc->cctx_msg != NULL)
		dmarcf_cleanup(ctx);

	if (conf->conf_ignoreauthclients &&
	    dmarcf_getsymval(ctx, "{auth_authen}") != NULL)
		return SMFIS_ACCEPT;

	dfc = (DMARCF_MSGCTX) malloc(sizeof(struct dmarcf_msgctx));
	if (dfc == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		return SMFIS_TEMPFAIL;
	}

	memset(dfc, '\0', sizeof(struct dmarcf_msgctx));

	cc->cctx_msg = dfc;

	dfc->mctx_jobid = JOBIDUNKNOWN;
	dfc->mctx_spfresult = -1;

	dfc->mctx_histbuf = dmarcf_dstring_new(BUFRSZ, 0);
	if (dfc->mctx_histbuf == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		return SMFIS_TEMPFAIL;
	}

	if (cc->cctx_dmarc != NULL)
		(void) opendmarc_policy_connect_rset(cc->cctx_dmarc);

	if (envfrom[0] != NULL)
	{
		size_t len;
		unsigned char *p;
		unsigned char *q;

#if WITH_SPF
		strncpy(cc->cctx_rawmfrom, envfrom[0],
			sizeof cc->cctx_rawmfrom - 1);
#endif
		strncpy(dfc->mctx_envfrom, envfrom[0],
		        sizeof dfc->mctx_envfrom - 1);

		len = strlen(dfc->mctx_envfrom);
		p = dfc->mctx_envfrom;
		q = dfc->mctx_envfrom + len - 1;

		while (len >= 2 && *p == '<' && *q == '>')
		{
			p++;
			q--;
			len -= 2;
		}

		if (p != dfc->mctx_envfrom)
		{
			*(q + 1) = '\0';
			memmove(dfc->mctx_envfrom, p, len + 1);
		}

		p = strchr(dfc->mctx_envfrom, '@');
		if (p != NULL)
			strncpy(dfc->mctx_envdomain, p + 1, strlen(p + 1));
	}

	return SMFIS_CONTINUE;
}

/*
**  MLFI_HEADER -- handler for mail headers; stores the header in a vector
**                 of headers for later perusal, removing RFC822 comment
**                 substrings
**
**  Parameters:
**  	ctx -- milter context
**  	headerf -- header
**  	headerv -- value
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	DMARCF_MSGCTX dfc;
	DMARCF_CONNCTX cc;
	struct dmarcf_header *newhdr;
	struct dmarcf_config *conf;

	assert(ctx != NULL);
	assert(headerf != NULL);
	assert(headerv != NULL);

	cc = (DMARCF_CONNCTX) dmarcf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	newhdr = (struct dmarcf_header *) malloc(sizeof(struct dmarcf_header));
	if (newhdr == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		dmarcf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	(void) memset(newhdr, '\0', sizeof(struct dmarcf_header));

	newhdr->hdr_name = strdup(headerf);
	newhdr->hdr_value = strdup(headerv);
	newhdr->hdr_next = NULL;
	newhdr->hdr_prev = dfc->mctx_hqtail;

	if (newhdr->hdr_name == NULL || newhdr->hdr_value == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		TRYFREE(newhdr->hdr_name);
		TRYFREE(newhdr->hdr_value);
		TRYFREE(newhdr);
		dmarcf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	if (dfc->mctx_hqhead == NULL)
		dfc->mctx_hqhead = newhdr;

	if (dfc->mctx_hqtail != NULL)
		dfc->mctx_hqtail->hdr_next = newhdr;

	dfc->mctx_hqtail = newhdr;

	return SMFIS_CONTINUE;
}

/*
**  MLFI_EOM -- handler called at the end of the message; we can now decide
**              based on the configuration if and how to add the text
**              to this message, then release resources
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_eom(SMFICTX *ctx)
{
	_Bool wspf = FALSE;
	int c;
	int pc;
	int policy;
	int status;
	int adkim;
	int aspf;
	int pct;
	int p;
	int sp;
	int align_dkim;
	int align_spf;
	int result;
	sfsistat ret = SMFIS_CONTINUE;
	OPENDMARC_STATUS_T ostatus;
	OPENDMARC_STATUS_T apused;
	char *apolicy = NULL;
	char *aresult = NULL;
	char *adisposition = NULL;
	char *hostname = NULL;
	char *authservid = NULL;
	char *spfaddr;
	DMARCF_CONNCTX cc;
	DMARCF_MSGCTX dfc;
	struct dmarcf_config *conf;
	struct dmarcf_header *hdr;
	struct dmarcf_header *from;
	u_char *reqhdrs_error = NULL;
	u_char *user;
	u_char *domain;
	u_char *bang;
	u_char **ruv;
	unsigned char header[MAXHEADER + 1];
	unsigned char addrbuf[BUFRSZ + 1];
	unsigned char replybuf[BUFRSZ + 1];
	unsigned char pdomain[MAXHOSTNAMELEN + 1];
	struct authres ar;

	assert(ctx != NULL);

	cc = (DMARCF_CONNCTX) dmarcf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	/*
	**  If necessary, try again to get the job ID in case it came down
	**  later than expected (e.g. postfix).
	*/

	if (strcmp((char *) dfc->mctx_jobid, JOBIDUNKNOWN) == 0)
	{
		dfc->mctx_jobid = (u_char *) dmarcf_getsymval(ctx, "i");
		if (dfc->mctx_jobid == NULL)
		{
			if (no_i_whine && conf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "WARNING: symbol 'i' not available");
				no_i_whine = FALSE;
			}
			dfc->mctx_jobid = (u_char *) JOBIDUNKNOWN;
		}
	}

	/* get hostname; used in software header and new MIME boundaries */
	hostname = dmarcf_getsymval(ctx, "j");
	if (hostname == NULL)
		hostname = myhostname;

	/* select authserv-id to use when generating result headers */
	authservid = conf->conf_authservid;
	if (authservid == NULL)
	{
		authservid = hostname;

		if (conf->conf_dolog)
		{
			syslog(LOG_INFO, "implicit authentication service: %s",
			       authservid);
		}
	}

	/* ensure there was a From field */
	from = dmarcf_findheader(dfc, "From", 0);

	/* verify RFC5322-required headers (RFC5322 3.6) */
	if (from == NULL ||
	    dmarcf_findheader(dfc, "From", 1) != NULL)
		reqhdrs_error = "not exactly one From field";

	if (dmarcf_findheader(dfc, "Date", 0) == NULL ||
	    dmarcf_findheader(dfc, "Date", 1) != NULL)
		reqhdrs_error = "not exactly one Date field";

	if (dmarcf_findheader(dfc, "Reply-To", 1) != NULL)
		reqhdrs_error = "multiple Reply-To fields";

	if (dmarcf_findheader(dfc, "To", 1) != NULL)
		reqhdrs_error = "multiple To fields";

	if (dmarcf_findheader(dfc, "Cc", 1) != NULL)
		reqhdrs_error = "multiple Cc fields";

	if (dmarcf_findheader(dfc, "Bcc", 1) != NULL)
		reqhdrs_error = "multiple Bcc fields";

	if (dmarcf_findheader(dfc, "Message-Id", 1) != NULL)
		reqhdrs_error = "multiple Message-Id fields";

	if (dmarcf_findheader(dfc, "In-Reply-To", 1) != NULL)
		reqhdrs_error = "multiple In-Reply-To fields";

	if (dmarcf_findheader(dfc, "References", 1) != NULL)
		reqhdrs_error = "multiple References fields";

	if (dmarcf_findheader(dfc, "Subject", 1) != NULL)
		reqhdrs_error = "multiple Subject fields";

	if (conf->conf_reqhdrs && reqhdrs_error != NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO,
			       "%s: RFC5322 requirement error: %s",
			       dfc->mctx_jobid, reqhdrs_error);
		}

		return SMFIS_REJECT;
	}

	/* if there was no From:, there's nothing to process past here */
	if (from == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO,
			       "%s: RFC5322 requirement error: missing From field; accepting",
			       dfc->mctx_jobid);
		}

		return SMFIS_ACCEPT;
	}

	/* extract From: domain */
	memset(addrbuf, '\0', sizeof addrbuf);
	strncpy(addrbuf, from->hdr_value, sizeof addrbuf - 1);
	status = dmarcf_mail_parse(addrbuf, &user, &domain);
	if (status != 0 || user == NULL || domain == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "%s: unable to parse From header field",
			       dfc->mctx_jobid);
		}

		if (conf->conf_reqhdrs)
			return SMFIS_REJECT;
		else
			return SMFIS_ACCEPT;
	}

	if (conf->conf_ignoredomains != NULL &&
	    dmarcf_match(domain, conf->conf_ignoredomains, TRUE))
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO, "%s: ignoring mail from %s",
			       dfc->mctx_jobid, domain);
		}

		return SMFIS_ACCEPT;
	}

	strncpy(dfc->mctx_fromdomain, domain, sizeof dfc->mctx_fromdomain - 1);

	ostatus = opendmarc_policy_store_from_domain(cc->cctx_dmarc,
	                                             from->hdr_value);
	if (ostatus != DMARC_PARSE_OKAY)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "%s: opendmarc_policy_store_from_domain() returned status %d",
			       dfc->mctx_jobid, ostatus);
		}

		return SMFIS_TEMPFAIL;
	}

	/* first part of the history buffer */
	dmarcf_dstring_printf(dfc->mctx_histbuf, "job %s\n", dfc->mctx_jobid);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "reporter %s\n", hostname);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "received %ld\n", time(NULL));
	dmarcf_dstring_printf(dfc->mctx_histbuf, "ipaddr %s\n", cc->cctx_ipstr);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "from %s\n",
	                      dfc->mctx_fromdomain);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "mfrom %s\n",
	                      dfc->mctx_envdomain);

	/*
	**  Walk through Authentication-Results fields and pull out data.
	*/

	for (hdr = dfc->mctx_hqhead, c = 0;
	     hdr != NULL;
	     hdr = hdr->hdr_next, c++)
	{
		/* skip it if it's not Authentication-Results */
		if (strcasecmp(hdr->hdr_name, AUTHRESHDRNAME) != 0)
			continue;

		/* parse it */
		memset(&ar, '\0', sizeof ar);
		if (ares_parse(hdr->hdr_value, &ar) != 0)
			continue;

		/* skip it if it's not one of ours */
		if (strcasecmp(ar.ares_host, authservid) != 0 &&
		    (conf->conf_trustedauthservids == NULL ||
		     !dmarcf_match(ar.ares_host, conf->conf_trustedauthservids,
		                   FALSE)))
		{
			unsigned char *slash;

			if (!conf->conf_authservidwithjobid)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_DEBUG,
					       "%s ignoring Authentication-Results at %d from %s",
					       dfc->mctx_jobid, c,
					       ar.ares_host);
				}

				continue;
			}

			slash = (unsigned char *) strchr(ar.ares_host, '/');
			if (slash == NULL)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_DEBUG,
					       "%s ignoring Authentication-Results at %d from %s",
					       dfc->mctx_jobid, c,
					       ar.ares_host);
				}

				continue;
			}

			*slash = '\0';
			if ((strcasecmp(ar.ares_host, authservid) != 0 &&
			     (conf->conf_trustedauthservids == NULL ||
			      !dmarcf_match(ar.ares_host,
			                    conf->conf_trustedauthservids,
			                    FALSE))) ||
			    strcmp(slash + 1, dfc->mctx_jobid) != 0)
			{
				*slash = '/';

				if (conf->conf_dolog)
				{
					syslog(LOG_DEBUG,
					       "%s ignoring Authentication-Results at %d from %s",
					       dfc->mctx_jobid, c,
					       ar.ares_host);
				}

				continue;
			}

			*slash = '/';
		}

		/* walk through what was found */
		for (c = 0; c < ar.ares_count; c++)
		{
			if (ar.ares_result[c].result_method == ARES_METHOD_SPF
#if WITH_SPF
			    && !conf->conf_spfignoreresults
#endif
			)
			{
				int spfmode;

				dfc->mctx_spfresult = ar.ares_result[c].result_result;

				if (ar.ares_result[c].result_result != ARES_RESULT_PASS)
					continue;

				spfaddr = NULL;
				spfmode = DMARC_POLICY_SPF_ORIGIN_HELO;

				memset(addrbuf, '\0', sizeof addrbuf);

				for (pc = 0;
				     pc < ar.ares_result[c].result_props;
				     pc++)
				{
					if (ar.ares_result[c].result_ptype[pc] == ARES_PTYPE_SMTP)
					{
						if (strcasecmp(ar.ares_result[c].result_property[pc],
					                       "mailfrom") == 0)
						{
							spfaddr = ar.ares_result[c].result_value[pc];
							if (strchr(spfaddr, '@') != NULL)
							{
								strncpy(addrbuf,
								        spfaddr,
								        sizeof addrbuf - 1);
							}
							else
							{
								snprintf(addrbuf,
								         sizeof addrbuf,
								         "UNKNOWN@%s",
								         spfaddr);
							}

							spfmode = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
						}
						else if (strcasecmp(ar.ares_result[c].result_property[pc],
					                           "helo") == 0 &&
						         addrbuf[0] == '\0')
						{
							spfaddr = ar.ares_result[c].result_value[pc];
							snprintf(addrbuf,
							         sizeof addrbuf,
							         "UNKNOWN@%s",
							         spfaddr);
							spfmode = DMARC_POLICY_SPF_ORIGIN_HELO;
						}
					}
				}

				if (spfaddr == NULL)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: can't extract SPF address from Authentication-Results",
						       dfc->mctx_jobid);
					}

					continue;
				}

				status = dmarcf_mail_parse(addrbuf, &user,
				                           &domain);
				if (status != 0 || domain == NULL ||
				    domain[0] == '\0')
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: unable to parse validated SPF address <%s>",
						       dfc->mctx_jobid,
						       spfaddr);
					}

					continue;
				}

				ostatus = opendmarc_policy_store_spf(cc->cctx_dmarc,
				                                     domain,
				                                     DMARC_POLICY_SPF_OUTCOME_PASS,
				                                     spfmode,
				                                     NULL);
				                                     
				if (ostatus != DMARC_PARSE_OKAY)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: opendmarc_policy_store_spf() returned status %d",
						       dfc->mctx_jobid, ostatus);
					}

					return SMFIS_TEMPFAIL;
				}

				dmarcf_dstring_printf(dfc->mctx_histbuf,
				                      "spf %d\n",
				                      dfc->mctx_spfresult);
				wspf = TRUE;
			}
			else if (ar.ares_result[c].result_method == ARES_METHOD_DKIM)
			{
				domain = NULL;

				for (pc = 0;
				     pc < ar.ares_result[c].result_props;
				     pc++)
				{
					if (ar.ares_result[c].result_ptype[pc] == ARES_PTYPE_HEADER)
					{
						if (ar.ares_result[c].result_property[pc][0] == 'd')
						{
							domain = ar.ares_result[c].result_value[pc];
						}
					}
				}

				if (domain == NULL)
					continue;

				dmarcf_dstring_printf(dfc->mctx_histbuf,
				                      "dkim %s %d\n", domain,
				                      ar.ares_result[c].result_result);

				if (ar.ares_result[c].result_result != ARES_RESULT_PASS)
					continue;

		                                     
				ostatus = opendmarc_policy_store_dkim(cc->cctx_dmarc,
				                                      domain,
				                                      DMARC_POLICY_DKIM_OUTCOME_PASS,
				                                      NULL);

				if (ostatus != DMARC_PARSE_OKAY)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: opendmarc_policy_store_from_dkim() returned status %d",
						       dfc->mctx_jobid, ostatus);
					}

					return SMFIS_TEMPFAIL;
				}
			}
		}
	}

	/* 
	**  If we didn't get Authentication-Results for SPF, parse any
	**  Received-SPF we might have.
	*/

	if (!wspf
#if WITH_SPF
	    && !conf->conf_spfignoreresults
#endif
	)
	{
		for (hdr = dfc->mctx_hqhead;
		     hdr != NULL && !wspf;
		     hdr = hdr->hdr_next)
		{
			if (strcasecmp(hdr->hdr_name, RECEIVEDSPF) == 0)
			{
				int spfres;
				int spfmode;

				if (dfc->mctx_fromdomain[0] == '\0')
					spfmode = DMARC_POLICY_SPF_ORIGIN_HELO;
				else
					spfmode = DMARC_POLICY_SPF_ORIGIN_MAILFROM;

				spfres = dmarcf_parse_received_spf(hdr->hdr_value);

				dmarcf_dstring_printf(dfc->mctx_histbuf,
				                      "spf %d\n", spfres);

				dfc->mctx_spfresult = spfres;

				switch (dfc->mctx_spfresult)
				{
				    case ARES_RESULT_PASS:
					spfres = DMARC_POLICY_SPF_OUTCOME_PASS;
					break;

				    case ARES_RESULT_NONE:
					spfres = DMARC_POLICY_SPF_OUTCOME_NONE;
					break;

				    case ARES_RESULT_TEMPERROR:
					spfres = DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
					break;

				    case ARES_RESULT_FAIL:
				    case ARES_RESULT_NEUTRAL:
				    case ARES_RESULT_SOFTFAIL:
					spfres = DMARC_POLICY_SPF_OUTCOME_FAIL;
					break;

				    default: /* e.g. ARES_RESULT_PERMERROR */
					spfres = DMARC_POLICY_SPF_OUTCOME_NONE;
					break;
				}

				/* use the MAIL FROM domain */
				ostatus = opendmarc_policy_store_spf(cc->cctx_dmarc,
				                                     dfc->mctx_envdomain,
				                                     spfres,
				                                     spfmode,
				                                     NULL);
				wspf = TRUE;
			}
		}
	}

	/*
	**  Interact with libopendmarc.
	*/

	if (!wspf)
	{
#if WITH_SPF
		if (conf->conf_spfselfvalidate)
		{
			int spf_result;
			char human[512];
			int used_mfrom;
			char *use_domain;
			int spf_mode;
			char *pass_fail;

# if HAVE_SPF2_H
			spf_result = opendmarc_spf2_test(
# else /* HAVE_SPF2_H */
			spf_result = opendmarc_spf_test(
# endif /* HAVE_SPF2_H */
				cc->cctx_ipstr,
				cc->cctx_rawmfrom,
				cc->cctx_helo,
				NULL,
				FALSE,
				human,
				sizeof human,
				&used_mfrom);
			if (used_mfrom == TRUE)
			{
				use_domain = dfc->mctx_envfrom;
				spf_mode   = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
			}
			else
			{
				use_domain = cc->cctx_helo;
				spf_mode   = DMARC_POLICY_SPF_ORIGIN_HELO;
			}
			ostatus = opendmarc_policy_store_spf(cc->cctx_dmarc, 
				                                     use_domain,
				                                     spf_result,
				                                     spf_mode,
				                                     human);
			switch (spf_result)
			{
			    case DMARC_POLICY_SPF_OUTCOME_PASS:
				pass_fail = "pass";
				dfc->mctx_spfresult = ARES_RESULT_PASS;
				break;

			    case DMARC_POLICY_SPF_OUTCOME_NONE:
				pass_fail = "none";
				dfc->mctx_spfresult = ARES_RESULT_NONE;
				break;

			    case DMARC_POLICY_SPF_OUTCOME_TMPFAIL:
				pass_fail = "tempfail";
				dfc->mctx_spfresult = ARES_RESULT_TEMPERROR;
				break;

			    case DMARC_POLICY_SPF_OUTCOME_FAIL:
				dfc->mctx_spfresult = ARES_RESULT_FAIL;
				pass_fail = "fail";
				break;

			    default:
				dfc->mctx_spfresult = ARES_RESULT_PERMERROR;
				pass_fail = "permerror";
				break;
			}

			if (spf_mode == DMARC_POLICY_SPF_ORIGIN_HELO)
			{
				snprintf(header, sizeof header,
					 "%s; spf=%s smtp.helo=%s",
					 authservid, pass_fail, use_domain);
			}
			else
			{
				snprintf(header, sizeof header,
					 "%s; spf=%s smtp.mailfrom=%s",
					 authservid, pass_fail, use_domain);
			}

			if (dmarcf_insheader(ctx, 1, AUTHRESULTSHDR,
					     header) == MI_FAILURE)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: %s header add failed",
					       dfc->mctx_jobid,
					       AUTHRESULTSHDR);
				}
			}

			if (conf->conf_dolog)
			{
				char *mode;

				if (spf_mode == DMARC_POLICY_SPF_ORIGIN_HELO)
					mode = "helo";
				else
					mode = "mailfrom";

				syslog(LOG_INFO,
				       "%s: SPF(%s): %s %s",
				       dfc->mctx_jobid,
				       mode,
				       use_domain,
				       pass_fail);
			}
		}
#endif /* WITH_SPF */

		dmarcf_dstring_printf(dfc->mctx_histbuf, "spf %d\n",
		                      dfc->mctx_spfresult);
	}

	ostatus = opendmarc_policy_query_dmarc(cc->cctx_dmarc,
	                                       dfc->mctx_fromdomain);
	if (ostatus == DMARC_PARSE_ERROR_NULL_CTX ||
	    ostatus == DMARC_PARSE_ERROR_EMPTY)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "%s: opendmarc_policy_query_dmarc(%s) returned status %d",
			       dfc->mctx_jobid, dfc->mctx_fromdomain, ostatus);
		}

		return SMFIS_TEMPFAIL;
	}
	else if (ostatus == DMARC_PARSE_ERROR_BAD_VERSION ||
	         ostatus == DMARC_PARSE_ERROR_BAD_VALUE ||
	         ostatus == DMARC_PARSE_ERROR_NO_REQUIRED_P ||
	         ostatus == DMARC_PARSE_ERROR_NO_DOMAIN)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "%s: opendmarc_policy_query_dmarc(%s) returned status %d",
			       dfc->mctx_jobid, dfc->mctx_fromdomain, ostatus);
		}

		snprintf(header, sizeof header,
		         "%s; dmarc=permerror header.from=%s",
		         authservid, dfc->mctx_fromdomain);

		if (dmarcf_insheader(ctx, 1, AUTHRESULTSHDR,
		                     header) == MI_FAILURE)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: %s header add failed",
				       dfc->mctx_jobid,
				       AUTHRESULTSHDR);
			}
		}

		return SMFIS_ACCEPT;
	}

	memset(pdomain, '\0', sizeof pdomain);
	opendmarc_policy_fetch_utilized_domain(cc->cctx_dmarc,
	                                       pdomain, sizeof pdomain);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "pdomain %s\n", pdomain);

	policy = opendmarc_get_policy_to_enforce(cc->cctx_dmarc);
	if (ostatus == DMARC_DNS_ERROR_NO_RECORD)
		policy = DMARC_POLICY_ABSENT;
	dmarcf_dstring_printf(dfc->mctx_histbuf, "policy %d\n", policy);

	ruv = opendmarc_policy_fetch_rua(cc->cctx_dmarc, NULL, 0, TRUE);
	if (ruv != NULL)
	{
		for (c = 0; ruv[c] != NULL; c++)
		{
			dmarcf_dstring_printf(dfc->mctx_histbuf, "rua %s\n",
			                      ruv[c]);
		}
	}
	else
	{
		dmarcf_dstring_printf(dfc->mctx_histbuf, "rua -\n");
	}

	opendmarc_policy_fetch_pct(cc->cctx_dmarc, &pct);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "pct %d\n", pct);

	opendmarc_policy_fetch_adkim(cc->cctx_dmarc, &adkim);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "adkim %d\n", adkim);

	opendmarc_policy_fetch_aspf(cc->cctx_dmarc, &aspf);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "aspf %d\n", aspf);

	opendmarc_policy_fetch_p(cc->cctx_dmarc, &p);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "p %d\n", p);

	opendmarc_policy_fetch_sp(cc->cctx_dmarc, &sp);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "sp %d\n", sp);

	opendmarc_policy_fetch_alignment(cc->cctx_dmarc, &align_dkim,
	                                 &align_spf);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "align_dkim %d\n",
	                      align_dkim);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "align_spf %d\n", align_spf);

	/* prepare human readable policy string for later processing */
	apused = opendmarc_get_policy_token_used(cc->cctx_dmarc);
	switch (apused == DMARC_USED_POLICY_IS_SP ? sp : p)
	{
	  case DMARC_RECORD_P_QUARANTINE:
		apolicy = "quarantine";
		break;

	  case DMARC_RECORD_P_REJECT:
		apolicy = "reject";
		break;

	  case DMARC_RECORD_P_UNSPECIFIED:
	  case DMARC_RECORD_P_NONE:
	  default:
		apolicy = "none";
		break;
	}

	/*
	**  Generate a failure report.
	*/

	ruv = opendmarc_policy_fetch_ruf(cc->cctx_dmarc, NULL, 0, TRUE);
	if ((policy == DMARC_POLICY_REJECT ||
	     policy == DMARC_POLICY_QUARANTINE ||
	     (conf->conf_afrfnone && policy == DMARC_POLICY_NONE)) &&
	    conf->conf_afrf &&
	    (conf->conf_afrfbcc != NULL || ruv != NULL))
	{
		_Bool first = TRUE;

		if (dfc->mctx_afrf == NULL)
		{
			dfc->mctx_afrf = dmarcf_dstring_new(BUFRSZ, 0);

			if (dfc->mctx_afrf == NULL)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: unable to create buffer for failure report",
					       dfc->mctx_jobid);
				}

				return SMFIS_TEMPFAIL;
			}
		}
		else
		{
			dmarcf_dstring_blank(dfc->mctx_afrf);
		}

		if (conf->conf_afrfas != NULL)
		{
			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "From: %s\n",
			                      conf->conf_afrfas);
		}
		else
		{
			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "From: %s <%s@%s>\n",
			                      DMARCF_PRODUCT,
			                      myname, hostname);
		}

		for (c = 0; ruv != NULL && ruv[c] != NULL; c++)
		{
			if (strncasecmp(ruv[c], "mailto:", 7) != 0)
				continue;

			bang = strchr(ruv[c], '!');
			if (bang != NULL)
				*bang = '\0';

			if (ruv[c][7] == '\0')
				continue;

			if (first)
			{
				dmarcf_dstring_cat(dfc->mctx_afrf, "To: ");
				first = FALSE;
			}
			else
			{
				dmarcf_dstring_cat(dfc->mctx_afrf, ", ");
			}

			dmarcf_dstring_cat(dfc->mctx_afrf, &ruv[c][7]);
		}

		if (conf->conf_afrfbcc != NULL)
		{
			if (first)
			{
				dmarcf_dstring_cat(dfc->mctx_afrf, "To: ");
				dmarcf_dstring_cat(dfc->mctx_afrf,
				                   conf->conf_afrfbcc);
				first = FALSE;
			}
		}

		if (!first)
		{
			time_t now;
			struct dmarcf_header *h;
			struct tm *tm;
			FILE *out;
			char timebuf[BUFRSZ];

			/* finish To: from above */
			dmarcf_dstring_cat(dfc->mctx_afrf, "\n");

			/* Bcc: */
			if (ruv != NULL && conf->conf_afrfbcc != NULL)
			{
				dmarcf_dstring_cat(dfc->mctx_afrf, "Bcc: ");
				dmarcf_dstring_cat(dfc->mctx_afrf,
				                   conf->conf_afrfbcc);
				dmarcf_dstring_cat(dfc->mctx_afrf, "\n");
			}
			
			/* Date: */
			(void) time(&now);
			tm = localtime(&now);
			(void) strftime(timebuf, sizeof timebuf,
			                "%a, %e %b %Y %H:%M:%S %z (%Z)", tm);
			dmarcf_dstring_printf(dfc->mctx_afrf, "Date: %s\n",
			                      timebuf);

			h = dmarcf_findheader(dfc, "subject", 0);
			if (h == NULL)
			{
				dmarcf_dstring_printf(dfc->mctx_afrf,
				                      "Subject: DMARC failure report for job %s\n",
				                      dfc->mctx_jobid);
			}
			else
			{
				dmarcf_dstring_printf(dfc->mctx_afrf,
				                      "Subject: FW: %s\n",
				                      h->hdr_value);
			}

			dmarcf_dstring_cat(dfc->mctx_afrf,
			                   "MIME-Version: 1.0\n");

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "Content-Type: multipart/report;"
			                      "\n\treport-type=feedback-report;"
			                      "\n\tboundary=\"%s:%s\"\n",
			                      hostname, dfc->mctx_jobid);

			dmarcf_dstring_cat(dfc->mctx_afrf, "\n");

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "--%s:%s\n"
			                      "Content-Type: text/plain\n\n",
			                      hostname, dfc->mctx_jobid);

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "This is an authentication "
			                      "failure report for an email "
			                      "message received from IP\n"
			                      "%s on %s.\n\n",
			                      cc->cctx_ipstr, timebuf);

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "--%s:%s\n"
			                      "Content-Type: message/feedback-report\n\n",
			                      hostname, dfc->mctx_jobid);

			dmarcf_dstring_cat(dfc->mctx_afrf,
			                   "Feedback-Type: auth-failure\n"
			                   "Version: 1\n");

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "User-Agent: %s/%s\n",
			                      DMARCF_PRODUCTNS, VERSION);

			dmarcf_dstring_cat(dfc->mctx_afrf,
			                   "Auth-Failure: dmarc\n");

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "Authentication-Results: %s; dmarc=fail header.from=%s\n",
			                      authservid,
			                      dfc->mctx_fromdomain);

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "Original-Envelope-Id: %s\n",
			                      dfc->mctx_jobid);

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "Original-Mail-From: %s\n",
			                      dfc->mctx_envfrom);

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "Source-IP: %s (%s)\n",
			                      cc->cctx_ipstr,
			                      cc->cctx_host);

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "Reported-Domain: %s\n\n",
			                      dfc->mctx_fromdomain);

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "--%s:%s\n"
			                      "Content-Type: text/rfc822-headers\n\n",
			                      hostname, dfc->mctx_jobid);

			for (h = dfc->mctx_hqhead; h != NULL; h = h->hdr_next)
			{
				dmarcf_dstring_printf(dfc->mctx_afrf,
				                      "%s: %s\n",
				                      h->hdr_name,
				                      h->hdr_value);
			}

			dmarcf_dstring_printf(dfc->mctx_afrf,
			                      "\n--%s:%s--\n",
			                      hostname, dfc->mctx_jobid);

			out = popen(conf->conf_reportcmd, "w");
			if (out == NULL)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR, "%s: popen(): %s",
					       dfc->mctx_jobid,
					       strerror(errno));
				}
			}
			else
			{
				fwrite(dmarcf_dstring_get(dfc->mctx_afrf),
				       1, dmarcf_dstring_len(dfc->mctx_afrf),
				       out);

				status = pclose(out);
				if (status != 0 && conf->conf_dolog)
				{
					int val;
					const char *how;

					if (WIFEXITED(status))
					{
						how = "exited with status";
						val = WEXITSTATUS(status);
					}
					else if (WIFSIGNALED(status))
					{
						how = "killed with signal";
						val = WTERMSIG(status);
					}
					else
					{
						how = "returned status";
						val = status;
					}

					syslog(LOG_ERR, "%s: pclose() %s %d",
					       dfc->mctx_jobid, how, val);
				}
			}
		}
	}

	/*
	**  Enact policy based on DMARC results.
	*/

	result = DMARC_RESULT_ACCEPT;

	switch (policy)
	{
	  case DMARC_POLICY_ABSENT:		/* No DMARC record found */
	  case DMARC_FROM_DOMAIN_ABSENT:	/* No From: domain */
		aresult = "none";
		ret = SMFIS_ACCEPT;
		result = DMARC_RESULT_ACCEPT;
		break;

	  case DMARC_POLICY_NONE:		/* Alignment failed, but policy is none: */
		aresult = "fail";		/* Accept and report */
		ret = SMFIS_ACCEPT;
		result = DMARC_RESULT_ACCEPT;
		break;

	  case DMARC_POLICY_PASS:		/* Explicit accept */
		aresult = "pass";
		ret = SMFIS_ACCEPT;
		result = DMARC_RESULT_ACCEPT;
		break;

	  case DMARC_POLICY_REJECT:		/* Explicit reject */
		aresult = "fail";

		if (conf->conf_rejectfail && random() % 100 < pct)
		{
			snprintf(replybuf, sizeof replybuf,
			         "rejected by DMARC policy for %s", pdomain);

			status = dmarcf_setreply(ctx, DMARC_REJECT_SMTP,
			                         DMARC_REJECT_ESC, replybuf);
			if (status != MI_SUCCESS && conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: smfi_setreply() failed",
				       dfc->mctx_jobid);
			}

			ret = SMFIS_REJECT;
			result = DMARC_RESULT_REJECT;
		}

		if (conf->conf_copyfailsto != NULL)
		{
			status = dmarcf_addrcpt(ctx, conf->conf_copyfailsto);
			if (status != MI_SUCCESS && conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: smfi_addrcpt() failed",
				       dfc->mctx_jobid);
			}
		}

		break;

	  case DMARC_POLICY_QUARANTINE:		/* Explicit quarantine */
		aresult = "fail";

		if (conf->conf_rejectfail && random() % 100 < pct)
		{
			snprintf(replybuf, sizeof replybuf,
			         "quarantined by DMARC policy for %s",
			         pdomain);

			status = smfi_quarantine(ctx, replybuf);
			if (status != MI_SUCCESS && conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: smfi_quarantine() failed",
				       dfc->mctx_jobid);
			}

			ret = SMFIS_ACCEPT;
			result = DMARC_RESULT_QUARANTINE;
		}

		if (conf->conf_copyfailsto != NULL)
		{
			status = dmarcf_addrcpt(ctx, conf->conf_copyfailsto);
			if (status != MI_SUCCESS && conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: smfi_addrcpt() failed",
				       dfc->mctx_jobid);
			}
		}

		break;

	  default:
		aresult = "temperror";
		ret = SMFIS_TEMPFAIL;
		result = DMARC_RESULT_TEMPFAIL;
		break;
	}

	/* prepare human readable dispositon string for later processing */
	switch (result)
	{
	  case DMARC_RESULT_REJECT:
		adisposition = "reject";
		break;

	  case DMARC_RESULT_QUARANTINE:
		adisposition = "quarantine";
		break;

	  default:
		adisposition = "none";
		break;
	}

	if (conf->conf_dolog)
	{
		syslog(LOG_INFO, "%s: %s %s", dfc->mctx_jobid,
		       dfc->mctx_fromdomain, aresult);
	}

	/* if the final action isn't TEMPFAIL or REJECT, add an A-R field */
	if (ret != SMFIS_TEMPFAIL && ret != SMFIS_REJECT)
	{
		snprintf(header, sizeof header,
		         "%s%s%s; dmarc=%s (p=%s dis=%s) header.from=%s",
		         authservid,
		         conf->conf_authservidwithjobid ? "/" : "",
		         conf->conf_authservidwithjobid ? dfc->mctx_jobid : "",
		         aresult, apolicy, adisposition, dfc->mctx_fromdomain);

		if (dmarcf_insheader(ctx, 1, AUTHRESULTSHDR,
		                     header) == MI_FAILURE)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: %s header add failed",
				       dfc->mctx_jobid,
				       AUTHRESULTSHDR);
			}
		}
	}

	dmarcf_dstring_printf(dfc->mctx_histbuf, "action %d\n", result);

	/*
	**  Record activity in the history file.
	*/

	if (conf->conf_historyfile != NULL &&
	    (conf->conf_recordall || ostatus != DMARC_DNS_ERROR_NO_RECORD))
	{
		FILE *f;

		f = fopen(conf->conf_historyfile, "a");
		if (f == NULL)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: %s: fopen(): %s",
				       dfc->mctx_jobid,
				       conf->conf_historyfile,
				       strerror(errno));
			}

			return SMFIS_TEMPFAIL;
		}

#ifdef LOCK_EX
		if (flock(fileno(f), LOCK_EX) != 0)
		{
			syslog(LOG_WARNING, "%s: %s: flock(LOCK_EX): %s",
#else
# ifdef F_LOCK
		if (lockf(fileno(f), F_LOCK, 0)  != 0)
		{
			syslog(LOG_WARNING, "%s: %s: lockf(F_LOCK): %s",
# endif
#endif /* LOCK_EX */
			       dfc->mctx_jobid,
			       conf->conf_historyfile,
			       strerror(errno));
		}

		/* write out the buffer */
		clearerr(f);
		fwrite(dmarcf_dstring_get(dfc->mctx_histbuf), 1,
		       dmarcf_dstring_len(dfc->mctx_histbuf), f);
		if (ferror(f) && conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: %s: fwrite(): %s",
			       dfc->mctx_jobid,
			       conf->conf_historyfile,
			       strerror(errno));
		}

#ifdef LOCK_EX
		if (flock(fileno(f), LOCK_UN) != 0)
		{
			syslog(LOG_WARNING, "%s: %s: flock(LOCK_UN): %s",
#else
# ifdef F_LOCK
		if (lockf(fileno(f), F_ULOCK, 0)  != 0)
		{
			syslog(LOG_WARNING, "%s: %s: lockf(F_ULOCK): %s",
# endif
#endif /* LOCK_EX */
			       dfc->mctx_jobid,
			       conf->conf_historyfile,
			       strerror(errno));
		}

		fclose(f);
	}

	if (conf->conf_addswhdr)
	{
		snprintf(header, sizeof header, "%s v%s %s %s",
		         DMARCF_PRODUCT, VERSION, hostname,
		         dfc->mctx_jobid != NULL ? dfc->mctx_jobid
		                                 : JOBIDUNKNOWN);

		if (dmarcf_insheader(ctx, 1, SWHEADERNAME,
		                     header) == MI_FAILURE)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: %s header add failed",
				       dfc->mctx_jobid,
				       SWHEADERNAME);
			}
		}
	}

	dmarcf_cleanup(ctx);

	return ret;
}

/*
**  MLFI_ABORT -- handler called if an earlier filter in the filter process
**                rejects the message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_abort(SMFICTX *ctx)
{
	dmarcf_cleanup(ctx);
	return SMFIS_CONTINUE;
}

/*
**  MLFI_CLOSE -- handler called on connection shutdown
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_close(SMFICTX *ctx)
{
	DMARCF_CONNCTX cc;

	dmarcf_cleanup(ctx);

	cc = (DMARCF_CONNCTX) dmarcf_getpriv(ctx);
	if (cc != NULL)
	{
		pthread_mutex_lock(&conf_lock);

		cc->cctx_config->conf_refcnt--;

		if (cc->cctx_config->conf_refcnt == 0 &&
		    cc->cctx_config != curconf)
			dmarcf_config_free(cc->cctx_config);

		pthread_mutex_unlock(&conf_lock);

		(void) opendmarc_policy_connect_shutdown(cc->cctx_dmarc);

		free(cc);
		dmarcf_setpriv(ctx, NULL);
	}

	return SMFIS_CONTINUE;
}

/*
**  smfilter -- the milter module description
*/

struct smfiDesc smfilter =
{
	DMARCF_PRODUCT,	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	0,		/* flags; updated in main() */
	mlfi_connect,	/* connection info filter */
#if WITH_SPF
	mlfi_helo,	/* SMTP HELO command filter */
#else
	NULL,		/* SMTP HELO command filter */
#endif
	mlfi_envfrom,	/* envelope sender filter */
	NULL,		/* envelope recipient filter */
	mlfi_header,	/* header filter */
	NULL,		/* end of header */
	NULL,		/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* shutdown */
#if SMFI_VERSION > 2
	NULL,		/* unrecognised command */
#endif
#if SMFI_VERSION > 3
	NULL,		/* DATA */
#endif
#if SMFI_VERSION >= 0x01000000
	mlfi_negotiate	/* negotiation callback */
#endif
};

/*
**  DMARCF_SIGHANDLER -- signal handler
**
**  Parameters:
**  	sig -- signal received
**
**  Return value:
**  	None.
*/

static void
dmarcf_sighandler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM || sig == SIGHUP)
	{
		diesig = sig;
		die = TRUE;
	}
	else if (sig == SIGUSR1)
	{
		if (conffile != NULL)
			reload = TRUE;
	}
}

/*
**  DMARCF_RELOADER -- reload signal thread
**
**  Parameters:
**  	vp -- void pointer required by thread API but not used
**
**  Return value:
**  	NULL.
*/

static void *
dmarcf_reloader(/* UNUSED */ void *vp)
{
	int sig;
	sigset_t mask;

	(void) pthread_detach(pthread_self());

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);

	while (!die)
	{
		(void) sigwait(&mask, &sig);

		if (conffile != NULL)
			reload = TRUE;
	}

	return NULL;
}

/*
**  DMARCF_KILLCHILD -- kill child process
**
**  Parameters:
**  	pid -- process ID to signal
**  	sig -- signal to use
**  	dolog -- log it?
**
**  Return value:
**  	None.
*/

static void
dmarcf_killchild(pid_t pid, int sig, _Bool dolog)
{
	if (kill(pid, sig) == -1 && dolog)
	{
		syslog(LOG_ERR, "kill(%d, %d): %s", pid, sig,
		       strerror(errno));
	}
}

/*
**  DMARCF_RESTART_CHECK -- initialize/check restart rate information
**
**  Parameters:
**  	n -- size of restart rate array to initialize/enforce
**  	t -- maximum time range for restarts (0 == init)
**
**  Return value:
**  	TRUE -- OK to continue
**  	FALSE -- error
*/

static _Bool
dmarcf_restart_check(int n, time_t t)
{
	static int idx;				/* last filled slot */
	static int alen;			/* allocated length */
	static time_t *list;

	if (t == 0)
	{
		alen = n * sizeof(time_t);

		list = (time_t *) malloc(alen);

		if (list == NULL)
			return FALSE;

		memset(list, '\0', alen);

		idx = 0;
		alen = n;

		return TRUE;
	}
	else
	{
		int which;

		time_t now;

		(void) time(&now);

		which = (idx - 1) % alen;
		if (which == -1)
			which = alen - 1;

		if (list[which] != 0 &&
		    list[which] + t > now)
			return FALSE;

		list[which] = t;
		idx++;

		return TRUE;
	}
}

/*
**  DMARCF_STDIO -- set up the base descriptors to go nowhere
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

static void
dmarcf_stdio(void)
{
	int devnull;

	/* this only fails silently, but that's OK */
	devnull = open(_PATH_DEVNULL, O_RDWR, 0);
	if (devnull != -1)
	{
		(void) dup2(devnull, 0);
		(void) dup2(devnull, 1);
		(void) dup2(devnull, 2);
		if (devnull > 2)
			(void) close(devnull);
	}

	(void) setsid();
}

/*
**  DMARCF_CONFIG_NEW -- get a new configuration handle
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new configuration handle, or NULL on error.
*/

static struct dmarcf_config *
dmarcf_config_new(void)
{
	struct dmarcf_config *new;

	new = (struct dmarcf_config *) malloc(sizeof(struct dmarcf_config));
	if (new == NULL)
		return NULL;

	memset(new, '\0', sizeof(struct dmarcf_config));

	new->conf_reportcmd = DEFREPORTCMD;

	return new;
}

/*
**  DMARCF_CONFIG_FREE -- destroy a configuration handle
**
**  Parameters:
**  	conf -- pointer to the configuration handle to be destroyed
**
**  Return value:
**  	None.
*/

static void
dmarcf_config_free(struct dmarcf_config *conf)
{
	assert(conf != NULL);
	assert(conf->conf_refcnt == 0);

	if (conf->conf_data != NULL)
		config_free(conf->conf_data);

	if (conf->conf_ignoredomains != NULL)
		dmarcf_freearray(conf->conf_ignoredomains);

	if (conf->conf_trustedauthservids != NULL)
		dmarcf_freearray(conf->conf_trustedauthservids);

	if (conf->conf_authservid != NULL)
		free(conf->conf_authservid);

	free(conf);
}

/*
**  USAGE -- print a usage message and exit
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s [options]\n"
	                "\t-A         \tenable auto-restart\n"
	                "\t-c file    \tconfiguration file\n"
	                "\t-f         \trun in the foreground\n"
	                "\t-l         \tlog to syslog\n"
	                "\t-n         \ttest configuration and exit\n"
	                "\t-p sockspec\tspecify milter socket\n"
	                "\t-P file    \twrite process ID to specified file\n"
	                "\t-t file    \tevaluate a single message\n"
	                "\t-u user    \ttry to become the named user\n"
	                "\t-v         \tincrease verbose output\n"
	                "\t-V         \tprint version and exit\n",
	        progname, progname);

	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	_Bool autorestart = FALSE;
	_Bool gotp = FALSE;
	_Bool dofork = TRUE;
	_Bool stricttest = FALSE;
	_Bool configonly = FALSE;
	int c;
	int status;
	int n;
	int verbose = 0;
	int maxrestarts = 0;
	int maxrestartrate_n = 0;
	int filemask = -1;
	int mdebug = 0;
#ifdef HAVE_SMFI_VERSION
	u_int mvmajor;
	u_int mvminor;
	u_int mvrelease;
#endif /* HAVE_SMFI_VERSION */
	time_t now;
	gid_t gid = (gid_t) -1;
	sigset_t sigset;
	time_t maxrestartrate_t = 0;
	pthread_t rt;
	const char *args = CMDLINEOPTS;
	FILE *f;
	struct passwd *pw = NULL;
	struct group *gr = NULL;
	char *become = NULL;
	char *chrootdir = NULL;
	char *extract = NULL;
	char *ignorefile = NULL;
	char *p;
	char *pidfile = NULL;
	char *testfile = NULL;
	struct config *cfg = NULL;
	char *end;
	char argstr[MAXARGV];
	char err[BUFRSZ + 1];
	OPENDMARC_LIB_T libopendmarc;

	/* initialize */
	testmode = FALSE;
	reload = FALSE;
	sock = NULL;
	no_i_whine = TRUE;
	conffile = NULL;
	ignore = NULL;

	memset(myhostname, '\0', sizeof myhostname);
	(void) gethostname(myhostname, sizeof myhostname);

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	(void) time(&now);
	srandom(now);

	curconf = dmarcf_config_new();
	if (curconf == NULL)
	{
		fprintf(stderr, "%s: malloc(): %s\n", progname,
		        strerror(errno));

		return EX_OSERR;
	}

	/* process command line options */
	while ((c = getopt(argc, argv, args)) != -1)
	{
		switch (c)
		{
		  case 'A':
			autorestart = TRUE;
			break;

		  case 'c':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			conffile = optarg;
			break;

		  case 'f':
			dofork = FALSE;
			break;

		  case 'l':
			curconf->conf_dolog = TRUE;
			break;

		  case 'n':
			configonly = TRUE;
			break;

		  case 'p':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			sock = optarg;
			(void) smfi_setconn(optarg);
			gotp = TRUE;
			break;

		  case 'P':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			pidfile = optarg;
			break;

		  case 't':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			testmode = TRUE;
			testfile = optarg;
			break;

		  case 'u':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			become = optarg;
			break;

		  case 'v':
			verbose++;
			break;

		  case 'V':
			printf("%s: %s v%s\n", progname, DMARCF_PRODUCT,
			       VERSION);
			printf("\tSMFI_VERSION 0x%x\n", SMFI_VERSION);
#ifdef HAVE_SMFI_VERSION
			(void) smfi_version(&mvmajor, &mvminor, &mvrelease);
			printf("\tlibmilter version %d.%d.%d\n",
			       mvmajor, mvminor, mvrelease);
#endif /* HAVE_SMFI_VERSION */
			dmarcf_optlist(stdout);
			return EX_OK;

		  default:
			return usage();
		}
	}

	if (optind != argc)
		return usage();

	/* if there's a default config file readable, use it */
	if (conffile == NULL && access(DEFCONFFILE, R_OK) == 0)
		conffile = DEFCONFFILE;

	if (conffile != NULL)
	{
		u_int line = 0;
		char *missing;
		char path[MAXPATHLEN + 1];

		cfg = config_load(conffile, dmarcf_config,
		                  &line, path, sizeof path);

		if (cfg == NULL)
		{
			fprintf(stderr,
			        "%s: %s: configuration error at line %u: %s\n",
			        progname, path, line,
			        config_error());
			dmarcf_config_free(curconf);
			return EX_CONFIG;
		}

#ifdef DEBUG
		(void) config_dump(cfg, stdout, NULL);
#endif /* DEBUG */

		missing = config_check(cfg, dmarcf_config);
		if (missing != NULL)
		{
			fprintf(stderr,
			        "%s: %s: required parameter \"%s\" missing\n",
			        progname, conffile, missing);
			config_free(cfg);
			dmarcf_config_free(curconf);
			return EX_CONFIG;
		}
	}

	if (dmarcf_config_load(cfg, curconf, err, sizeof err) != 0)
	{
		if (conffile == NULL)
			conffile = "(stdin)";
		fprintf(stderr, "%s: %s: %s\n", progname, conffile, err);
		config_free(cfg);
		dmarcf_config_free(curconf);
		return EX_CONFIG;
	}

	if (configonly)
	{
		config_free(cfg);
		dmarcf_config_free(curconf);
		return EX_OK;
	}

	if (extract)
	{
		int ret = EX_OK;

		if (cfg != NULL)
		{
			if (!config_validname(dmarcf_config, extract))
				ret = EX_DATAERR;
			else if (config_dump(cfg, stdout, extract) == 0)
				ret = EX_CONFIG;
			config_free(cfg);
			dmarcf_config_free(curconf);
		}
		return ret;
	}

	dolog = curconf->conf_dolog;
	curconf->conf_data = cfg;

	/*
	**  Use values found in the configuration file, if any.  Note that
	**  these are operational parameters for the filter (e.g which socket
	**  to use which userid to become, etc.) and aren't reloaded upon a
	**  reload signal.  Reloadable values are handled via the
	**  dmarcf_config_load() function, which has already been called.
	*/

	if (cfg != NULL)
	{
		if (!autorestart)
		{
			(void) config_get(cfg, "AutoRestart", &autorestart,
			                  sizeof autorestart);
		}

		if (autorestart)
		{
			char *rate = NULL;

			(void) config_get(cfg, "AutoRestartCount",
			                  &maxrestarts, sizeof maxrestarts);

			(void) config_get(cfg, "AutoRestartRate", &rate,
			                  sizeof rate);

			if (rate != NULL)
			{
				time_t t;
				char *q;

				p = strchr(rate, '/');
				if (p == NULL)
				{
					fprintf(stderr,
					        "%s: AutoRestartRate invalid\n",
					        progname);
					config_free(cfg);
					return EX_CONFIG;
				}

				*p = '\0';
				n = strtol(rate, &q, 10);
				if (n < 0 || *q != '\0')
				{
					fprintf(stderr,
					        "%s: AutoRestartRate invalid\n",
					        progname);
					config_free(cfg);
					return EX_CONFIG;
				}

				t = (time_t) strtoul(p + 1, &q, 10);
				switch (*q)
				{
				  case 'd':
				  case 'D':
					t *= 86400;
					break;

				  case 'h':
				  case 'H':
					t *= 3600;
					break;

				  case 'm':
				  case 'M':
					t *= 60;
					break;

				  case '\0':
				  case 's':
				  case 'S':
					break;

				  default:
					t = 0;
					break;
				}

				if (*q != '\0' && *(q + 1) != '\0')
					t = 0;

				if (t == 0)
				{
					fprintf(stderr,
					        "%s: AutoRestartRate invalid\n",
					        progname);
					config_free(cfg);
					return EX_CONFIG;
				}

				maxrestartrate_n = n;
				maxrestartrate_t = t;
			}
		}

		if (dofork)
		{
			(void) config_get(cfg, "Background", &dofork,
			                  sizeof dofork);
		}

		(void) config_get(cfg, "MilterDebug", &mdebug, sizeof mdebug);

		if (!gotp)
		{
			(void) config_get(cfg, "Socket", &sock, sizeof sock);
			if (sock != NULL)
			{
				gotp = TRUE;
				(void) smfi_setconn(sock);
			}
		}

		if (pidfile == NULL)
		{
			(void) config_get(cfg, "PidFile", &pidfile,
			                  sizeof pidfile);
		}

		(void) config_get(cfg, "UMask", &filemask, sizeof filemask);

		if (become == NULL)
		{
			(void) config_get(cfg, "Userid", &become,
			                  sizeof become);
		}

		(void) config_get(cfg, "ChangeRootDirectory", &chrootdir,
		                  sizeof chrootdir);

		(void) config_get(cfg, "IgnoreHosts", &ignorefile,
		                  sizeof ignorefile);
	}

	if (ignorefile != NULL)
	{
		if (!dmarcf_loadlist(ignorefile, &ignore))
		{
			fprintf(stderr,
			        "%s: can't load ignore list from %s: %s\n",
			        progname, ignorefile, strerror(errno));
			return EX_DATAERR;
		}
	}
	else if (!testmode)
	{
		dmarcf_addlist("127.0.0.1", &ignore);
	}

	if (!gotp && !testmode)
	{
		fprintf(stderr, "%s: milter socket must be specified\n",
		        progname);
		if (argc == 1)
			fprintf(stderr, "\t(use \"-?\" for help)\n");
		return EX_CONFIG;
	}

	/* suppress a bunch of things if we're in test mode */
	if (testmode)
	{
		curconf->conf_dolog = FALSE;
		autorestart = FALSE;
		dofork = FALSE;
		become = NULL;
		pidfile = NULL;
		chrootdir = NULL;
	}

	dmarcf_setmaxfd();

	/* prepare to change user if appropriate */
	if (become != NULL)
	{
		char *colon;

		/* see if there was a group specified; if so, validate */
		colon = strchr(become, ':');
		if (colon != NULL)
		{
			*colon = '\0';

			gr = getgrnam(colon + 1);
			if (gr == NULL)
			{
				char *q;

				gid = (gid_t) strtol(colon + 1, &q, 10);
				if (*q == '\0')
					gr = getgrgid(gid);

				if (gr == NULL)
				{
					if (curconf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "no such group or gid '%s'",
						       colon + 1);
					}

					fprintf(stderr,
					        "%s: no such group '%s'\n",
					        progname, colon + 1);

					return EX_DATAERR;
				}
			}
		}

		/* validate the user */
		pw = getpwnam(become);
		if (pw == NULL)
		{
			char *q;
			uid_t uid;

			uid = (uid_t) strtoul(become, &q, 10);
			if (*q == '\0')
				pw = getpwuid(uid);

			if (pw == NULL)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "no such user or uid '%s'",
					       become);
				}

				fprintf(stderr, "%s: no such user '%s'\n",
				        progname, become);

				return EX_DATAERR;
			}
		}

		if (gr == NULL)
			gid = pw->pw_gid;
		else
			gid = gr->gr_gid;
	}

	/* change root if requested */
	if (chrootdir != NULL)
	{
		/* warn if doing so as root without then giving up root */
		if (become == NULL && getuid() == 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "using ChangeRootDirectory without Userid not advised");
			}

			fprintf(stderr,
			        "%s: use of ChangeRootDirectory without Userid not advised\n",
			        progname);
		}

		/* change to the new root first */
		if (chdir(chrootdir) != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: chdir(): %s",
				       chrootdir, strerror(errno));
			}

			fprintf(stderr, "%s: %s: chdir(): %s\n", progname,
			        chrootdir, strerror(errno));
			return EX_OSERR;
		}

		/* now change the root */
		if (chroot(chrootdir) != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: chroot(): %s",
				       chrootdir, strerror(errno));
			}

			fprintf(stderr, "%s: %s: chroot(): %s\n", progname,
			        chrootdir, strerror(errno));
			return EX_OSERR;
		}
	}

	/* now enact the user change */
	if (become != NULL)
	{
		/* make all the process changes */
		if (getuid() != pw->pw_uid)
		{
			if (initgroups(pw->pw_name, gid) != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "initgroups(): %s",
					       strerror(errno));
				}

				fprintf(stderr, "%s: initgroups(): %s\n",
				        progname, strerror(errno));

				return EX_NOPERM;
			}
			else if (setgid(gid) != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "setgid(): %s",
					       strerror(errno));
				}

				fprintf(stderr, "%s: setgid(): %s\n", progname,
				        strerror(errno));

				return EX_NOPERM;
			}
			else if (setuid(pw->pw_uid) != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "setuid(): %s",
					       strerror(errno));
				}

				fprintf(stderr, "%s: setuid(): %s\n", progname,
				        strerror(errno));

				return EX_NOPERM;
			}
		}

		(void) endpwent();
	}
	else
	{
	}

	if (curconf->conf_enablecores)
	{
		_Bool enabled = FALSE;

#ifdef __linux__
		if (prctl(PR_SET_DUMPABLE, 1) == -1)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "prctl(): %s",
				       strerror(errno));
			}

			fprintf(stderr, "%s: prctl(): %s\n",
			        progname, strerror(errno));
		}
		else
		{
			enabled = TRUE;
		}
#endif /* __linux__ */

		if (!enabled)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "can't enable coredumps; continuing");
			}

			fprintf(stderr,
			        "%s: can't enable coredumps; continuing\n",
			        progname);
		}
	}

	die = FALSE;

	if (autorestart)
	{
		_Bool quitloop = FALSE;
		int restarts = 0;
		int status;
		pid_t pid;
		pid_t wpid;
		struct sigaction sa;

		if (dofork)
		{
			pid = fork();
			switch (pid)
			{
			  case -1:
				if (curconf->conf_dolog)
				{
					int saveerrno;

					saveerrno = errno;

					syslog(LOG_ERR, "fork(): %s",
					       strerror(errno));

					errno = saveerrno;
				}

				fprintf(stderr, "%s: fork(): %s\n",
				        progname, strerror(errno));

				return EX_OSERR;

			  case 0:
				dmarcf_stdio();
				break;

			  default:
				return EX_OK;
			}
		}

		if (pidfile != NULL)
		{
			f = fopen(pidfile, "w");
			if (f != NULL)
			{
				fprintf(f, "%ld\n", (long) getpid());
				(void) fclose(f);
			}
			else
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "can't write pid to %s: %s",
					       pidfile, strerror(errno));
				}
			}
		}

		sa.sa_handler = dmarcf_sighandler;
		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGHUP);
		sigaddset(&sa.sa_mask, SIGINT);
		sigaddset(&sa.sa_mask, SIGTERM);
		sigaddset(&sa.sa_mask, SIGUSR1);
		sa.sa_flags = 0;

		if (sigaction(SIGHUP, &sa, NULL) != 0 ||
		    sigaction(SIGINT, &sa, NULL) != 0 ||
		    sigaction(SIGTERM, &sa, NULL) != 0 ||
		    sigaction(SIGUSR1, &sa, NULL) != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "[parent] sigaction(): %s",
				       strerror(errno));
			}
		}

		if (maxrestartrate_n > 0)
			dmarcf_restart_check(maxrestartrate_n, 0);

		while (!quitloop)
		{
			status = dmarcf_socket_cleanup(sock);
			if (status != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "[parent] socket cleanup failed: %s",
					       strerror(status));
				}
				return EX_UNAVAILABLE;
			}

			pid = fork();
			switch (pid)
			{
			  case -1:
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "fork(): %s",
					       strerror(errno));
				}

				return EX_OSERR;

			  case 0:
				sa.sa_handler = SIG_DFL;

				if (sigaction(SIGHUP, &sa, NULL) != 0 ||
				    sigaction(SIGINT, &sa, NULL) != 0 ||
				    sigaction(SIGTERM, &sa, NULL) != 0)
				{
					if (curconf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "[child] sigaction(): %s",
						       strerror(errno));
					}
				}

				quitloop = TRUE;
				break;

			  default:
				for (;;)
				{
					wpid = wait(&status);

					if (wpid == -1 && errno == EINTR)
					{
						if (die)
						{
							dmarcf_killchild(pid,
							                diesig,
							                curconf->conf_dolog);
							while (wpid != pid)
								wpid = wait(&status);

							if (pidfile != NULL)
								(void) unlink(pidfile);

							exit(EX_OK);
						}
						else if (reload)
						{
							dmarcf_killchild(pid,
							                SIGUSR1,
							                curconf->conf_dolog);

							reload = FALSE;

							continue;
						}
					}

					if (pid != wpid)
						continue;

					if (wpid != -1 && curconf->conf_dolog)
					{
						if (WIFSIGNALED(status))
						{
							syslog(LOG_NOTICE,
							       "terminated with signal %d, restarting",
							       WTERMSIG(status));
						}
						else if (WIFEXITED(status))
						{
							if (WEXITSTATUS(status) == EX_CONFIG ||
							    WEXITSTATUS(status) == EX_SOFTWARE)
							{
								syslog(LOG_NOTICE,
								       "exited with status %d",
								       WEXITSTATUS(status));
								quitloop = TRUE;
							}
							else
							{
								syslog(LOG_NOTICE,
								       "exited with status %d, restarting",
								       WEXITSTATUS(status));
							}
						}
					}

					if (conffile != NULL)
						reload = TRUE;

					break;
				}
				break;
			}

			if (maxrestarts > 0 && restarts >= maxrestarts)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "maximum restart count exceeded");
				}

				return EX_UNAVAILABLE;
			}

			if (maxrestartrate_n > 0 &&
			    maxrestartrate_t > 0 &&
			    !dmarcf_restart_check(0, maxrestartrate_t))
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "maximum restart rate exceeded");
				}

				return EX_UNAVAILABLE;
			}

			restarts++;
		}
	}

	if (filemask != -1)
		(void) umask((mode_t) filemask);

	if (mdebug > 0)
		(void) smfi_setdbg(mdebug);

	if (!testmode)
	{
		/* try to clean up the socket */
		status = dmarcf_socket_cleanup(sock);
		if (status != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "socket cleanup failed: %s",
				       strerror(status));
			}

			fprintf(stderr, "%s: socket cleanup failed: %s\n",
				progname, strerror(status));

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_UNAVAILABLE;
		}

		smfilter.xxfi_flags = SMFIF_ADDHDRS|SMFIF_QUARANTINE;
#ifdef SMFIF_SETSYMLIST
		smfilter.xxfi_flags |= SMFIF_SETSYMLIST;
#endif /* SMFIF_SETSYMLIST */

		/* register with the milter interface */
		if (smfi_register(smfilter) == MI_FAILURE)
		{
			if (curconf->conf_dolog)
				syslog(LOG_ERR, "smfi_register() failed");

			fprintf(stderr, "%s: smfi_register() failed\n",
				progname);

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_UNAVAILABLE;
		}

#ifdef HAVE_SMFI_OPENSOCKET
		/* try to establish the milter socket */
		if (smfi_opensocket(FALSE) == MI_FAILURE)
		{
			if (curconf->conf_dolog)
				syslog(LOG_ERR, "smfi_opensocket() failed");

			fprintf(stderr, "%s: smfi_opensocket() failed\n",
				progname);

			return EX_UNAVAILABLE;
		}
#endif /* HAVE_SMFI_OPENSOCKET */
	}

	if (!autorestart && dofork)
	{
		pid_t pid;

		pid = fork();
		switch (pid)
		{
		  case -1:
			if (curconf->conf_dolog)
			{
				int saveerrno;

				saveerrno = errno;

				syslog(LOG_ERR, "fork(): %s", strerror(errno));

				errno = saveerrno;
			}

			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));

			return EX_OSERR;

		  case 0:
			dmarcf_stdio();
			break;

		  default:
			return EX_OK;
		}
	}

	/* write out the pid */
	if (!autorestart && pidfile != NULL)
	{
		f = fopen(pidfile, "w");
		if (f != NULL)
		{
			fprintf(f, "%ld\n", (long) getpid());
			(void) fclose(f);
		}
		else
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "can't write pid to %s: %s",
				       pidfile, strerror(errno));
			}
		}
	}

	/*
	**  Block SIGUSR1 for use of our reload thread, and SIGHUP, SIGINT
	**  and SIGTERM for use of libmilter's signal handling thread.
	*/

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGINT);
	status = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	if (status != 0)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "pthread_sigprocmask(): %s",
			       strerror(status));
		}

		fprintf(stderr, "%s: pthread_sigprocmask(): %s\n", progname,
		        strerror(status));

		return EX_OSERR;
	}

	pthread_mutex_init(&conf_lock, NULL);

	/* initialize libopendmarc */
	(void) memset(&libopendmarc, '\0', sizeof libopendmarc);
	if (curconf->conf_pslist != NULL)
	{
		libopendmarc.tld_type = OPENDMARC_TLD_TYPE_MOZILLA;
		strncpy(libopendmarc.tld_source_file, curconf->conf_pslist,
		        sizeof libopendmarc.tld_source_file - 1);
	}

	if (opendmarc_policy_library_init(&libopendmarc) != 0)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "opendmarc_policy_library_init() failed");
		}

		if (!autorestart && pidfile != NULL)
			(void) unlink(pidfile);

		return EX_OSERR;
	}

	/* figure out who I am */
	if (pw == NULL)
		pw = getpwuid(getuid());
	if (pw == NULL)
		myname = "postmaster";
	else
		myname = pw->pw_name;

	/* perform test mode */
	if (testfile != NULL)
	{
		status = dmarcf_testfiles(testfile, stricttest, verbose);
		return status;
	}

	if (curconf->conf_dolog)
	{
		memset(argstr, '\0', sizeof argstr);
		end = &argstr[sizeof argstr - 1];
		n = sizeof argstr;
		for (c = 1, p = argstr; c < argc && p < end; c++)
		{
			if (strchr(argv[c], ' ') != NULL)
			{
				status = snprintf(p, n, "%s \"%s\"",
				                  c == 1 ? "args:" : "",
				                  argv[c]);
			}
			else
			{
				status = snprintf(p, n, "%s %s",
				                  c == 1 ? "args:" : "",
				                  argv[c]);
			}

			p += status;
			n -= status;
		}

		syslog(LOG_INFO, "%s v%s starting (%s)", DMARCF_PRODUCT,
		       VERSION, argstr);

		memset(argstr, '\0', sizeof argstr);
		strlcpy(argstr, "(none)", sizeof argstr);
		n = sizeof argstr;
		for (c = 0;
		     curconf->conf_trustedauthservids != NULL &&
		     curconf->conf_trustedauthservids[c] != NULL;
		     c++)
		{
			if (c == 0)
			{
				strlcpy(argstr, 
				        curconf->conf_trustedauthservids[c],
				        n);
			}
			else
			{
				strlcat(argstr, ", ", n);
				strlcat(argstr,
				        curconf->conf_trustedauthservids[c],
				        n);
			}
		}

		syslog(LOG_INFO,
		       "additional trusted authentication services: %s",
		       argstr);
	}

	/* spawn the SIGUSR1 handler */
	status = pthread_create(&rt, NULL, dmarcf_reloader, NULL);
	if (status != 0)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "pthread_create(): %s",
			       strerror(status));
		}

		if (!autorestart && pidfile != NULL)
			(void) unlink(pidfile);

		return EX_OSERR;
	}

	/* call the milter mainline */
	errno = 0;
	status = smfi_main();

	/* shut down libopendmarc */
	(void) opendmarc_policy_library_shutdown(&libopendmarc);

	if (curconf->conf_dolog)
	{
		syslog(LOG_INFO,
		       "%s v%s terminating with status %d, errno = %d",
		       DMARCF_PRODUCT, VERSION, status, errno);
	}

	/* release memory */
	dmarcf_config_free(curconf);
	if (ignore != NULL)
		dmarcf_freelist(ignore);

	/* tell the reloader thread to die */
	die = TRUE;
	(void) raise(SIGUSR1);

	if (!autorestart && pidfile != NULL)
		(void) unlink(pidfile);

	return status;
}
