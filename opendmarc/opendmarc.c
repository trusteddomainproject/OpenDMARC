/*
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS
#endif /* ! _POSIX_PTHREAD_SEMANTICS */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
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
	int			mctx_spfalign;
	char *			mctx_jobid;
	struct dmarcf_header *	mctx_hqhead;
	struct dmarcf_header *	mctx_hqtail;
	struct dmarcf_dstring *	mctx_histbuf;
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
};
typedef struct dmarcf_connctx * DMARCF_CONNCTX;

/* DMARCF_CONFIG -- configuration object */
struct dmarcf_config
{
	_Bool			conf_deliver;
	_Bool			conf_dolog;
	_Bool			conf_enablecores;
	_Bool			conf_addswhdr;
	_Bool			conf_authservidwithjobid;
	unsigned int		conf_refcnt;
	unsigned int		conf_dnstimeout;
	struct config *		conf_data;
	char *			conf_tmpdir;
	char *			conf_authservid;
	char *			conf_historyfile;
	char *			conf_pslist;
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
sfsistat mlfi_envfrom __P((SMFICTX *, char **));
sfsistat mlfi_eoh __P((SMFICTX *));
sfsistat mlfi_eom __P((SMFICTX *));
sfsistat mlfi_header __P((SMFICTX *, char *, char *));
sfsistat mlfi_negotiate __P((SMFICTX *, unsigned long, unsigned long,
                                        unsigned long, unsigned long,
                                        unsigned long *, unsigned long *,
                                        unsigned long *, unsigned long *));

static void dmarcf_config_free __P((struct dmarcf_config *));
static struct dmarcf_config *dmarcf_config_new __P((void));
sfsistat dkimf_insheader __P((SMFICTX *, int, char *, char *));
sfsistat dkimf_setreply __P((SMFICTX *, char *, char *, char *));

/* globals */
_Bool dolog;
_Bool die;
_Bool reload;
_Bool no_i_whine;
_Bool testmode;
int diesig;
struct dmarcf_config *curconf;
char *progname;
char *conffile;
char *sock;
char myhostname[MAXHOSTNAMELEN + 1];
pthread_mutex_t conf_lock;

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

	return smfi_getsymval(ctx, sym);
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
		for (p = log_facilities; p != NULL; p++)
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
		else
		{
			conf->conf_authservid = strdup(myhostname);
		}

		(void) config_get(data, "AuthservIDWithJobID",
		                  &conf->conf_authservidwithjobid,
		                  sizeof conf->conf_authservidwithjobid);

		memset(basedir, '\0', sizeof basedir);
		str = NULL;
		(void) config_get(data, "BaseDirectory", &str, sizeof str);
		if (str != NULL)
			strncpy(basedir, str, sizeof basedir - 1);

		if (conf->conf_dnstimeout == DEFTIMEOUT)
		{
			(void) config_get(data, "DNSTimeout",
			                  &conf->conf_dnstimeout,
			                  sizeof conf->conf_dnstimeout);
		}

		(void) config_get(data, "EnableCoredumps",
		                  &conf->conf_enablecores,
		                  sizeof conf->conf_enablecores);

		(void) config_get(data, "AlwaysDeliver",
		                  &conf->conf_deliver,
		                  sizeof conf->conf_deliver);

		(void) config_get(data, "TemporaryDirectory",
		                  &conf->conf_tmpdir,
		                  sizeof conf->conf_tmpdir);

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

		if (curconf->conf_pslist != NULL)
		{
			/* XXX -- opendmarc_tld_shutdown() */
		}

		if (new->conf_pslist != NULL)
		{
			if (opendmarc_tld_read_file(new->conf_pslist, "#",
			                            NULL, NULL) != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "%s: read/parse error",
					       new->conf_pslist);
				}
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
	unsigned long reqactions = SMFIF_ADDHDRS;
	unsigned long wantactions = 0;
	unsigned long protosteps = (SMFIP_NOHELO |
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

	dfc->mctx_histbuf = dmarcf_dstring_new(BUFRSZ, 0);
	if (dfc->mctx_histbuf == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		return SMFIS_TEMPFAIL;
	}

	dfc->mctx_spfalign = -1;

	if (cc->cctx_dmarc != NULL)
		(void) opendmarc_policy_connect_rset(cc->cctx_dmarc);

	if (envfrom[0] != NULL)
	{
		size_t len;
		unsigned char *p;
		unsigned char *q;

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
	int c;
	int pc;
	int policy;
	int status;
	sfsistat ret = SMFIS_CONTINUE;
	OPENDMARC_STATUS_T ostatus;
	char *aresult = NULL;
	char *hostname = NULL;
	char *authservid = NULL;
	DMARCF_CONNCTX cc;
	DMARCF_MSGCTX dfc;
	struct dmarcf_config *conf;
	struct dmarcf_header *hdr;
	struct dmarcf_header *from;
	u_char *user;
	u_char *domain;
	u_char **ruav;
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
		authservid = hostname;

	/* extract From: domain */
	from = NULL;
	for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (strcasecmp(hdr->hdr_name, "from") == 0)
		{
			from = hdr;
			break;
		}
	}

	if (from == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: no From header field found",
			       dfc->mctx_jobid);
		}

		return SMFIS_ACCEPT;
	}

	memset(addrbuf, '\0', sizeof addrbuf);
	strncpy(addrbuf, from->hdr_value, sizeof addrbuf - 1);
	status = dmarcf_mail_parse(addrbuf, &user, &domain);
	if (status != 0)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: can't parse From header field",
			       dfc->mctx_jobid);
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

	for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		/* skip it if it's not Authentication-Results */
		if (strcasecmp(hdr->hdr_name, AUTHRESHDRNAME) != 0)
			continue;

		/* parse it */
		memset(&ar, '\0', sizeof ar);
		if (ares_parse(hdr->hdr_value, &ar) != 0)
			continue;

		/* skip it if it's not one of ours */
		if (strcasecmp(ar.ares_host, authservid) != 0)
		{
			size_t clen;
			unsigned char *slash;

			if (!conf->conf_authservidwithjobid)
				continue;

			slash = (unsigned char *) strchr(ar.ares_host, '/');
			if (slash == NULL)
				continue;

			clen = slash - &ar.ares_host[0] - 1;

			if (strncasecmp(ar.ares_host, authservid, clen) != 0 ||				    strcmp(slash + 1, dfc->mctx_jobid) != 0)
				continue;
		}

		/* walk through what was found */
		for (c = 0; c < ar.ares_count; c++)
		{
			if (ar.ares_result[c].result_method ==  ARES_METHOD_SPF)
			{
				int spfmode;

				dfc->mctx_spfresult = ar.ares_result[c].result_result;

				strncpy(addrbuf, dfc->mctx_envfrom,
				        sizeof addrbuf - 1);

				status = dmarcf_mail_parse(addrbuf, &user,
				                           &domain);
				if (status != 0)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: can't parse return path address",
						       dfc->mctx_jobid);
					}

					return SMFIS_ACCEPT;
				}

				spfmode = DMARC_POLICY_SPF_ORIGIN_HELO;

				for (pc = 0;
				     pc < ar.ares_result[c].result_props;
				     pc++)
				{
					if (ar.ares_result[c].result_ptype[pc] == ARES_PTYPE_SMTP &&
					    strcasecmp(ar.ares_result[c].result_property[pc],
					               "mailfrom") == 0)
						spfmode = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
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
						       "%s: opendmarc_policy_store_from_spf() returned status %d",
						       dfc->mctx_jobid, ostatus);
					}

					return SMFIS_TEMPFAIL;
				}

				dmarcf_dstring_printf(dfc->mctx_histbuf,
				                      "spf %d\n",
				                      dfc->mctx_spfresult);
				dmarcf_dstring_printf(dfc->mctx_histbuf,
				                      "aspf %d\n",
				                      dfc->mctx_spfalign);
			}
			else if (ar.ares_result[c].result_method ==  ARES_METHOD_DKIM)
			{
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
						else if (ar.ares_result[c].result_property[pc][0] == 'i')
						{
							char *at;

							at = strchr(ar.ares_result[c].result_value[pc], '@');
							if (at == NULL)
								domain = NULL;
							else
								domain = at + 1;
						}

					}
				}

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
	**  Interact with libopendmarc.
	*/

	opendmarc_policy_query_dmarc(cc->cctx_dmarc, dfc->mctx_fromdomain);

	memset(pdomain, '\0', sizeof pdomain);
	opendmarc_policy_fetch_utilized_domain(cc->cctx_dmarc,
	                                       pdomain, sizeof pdomain);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "pdomain %s\n", pdomain);

	policy = opendmarc_get_policy_to_enforce(cc->cctx_dmarc);
	dmarcf_dstring_printf(dfc->mctx_histbuf, "policy %d\n", policy);

	ruav = opendmarc_policy_fetch_rua(cc->cctx_dmarc, NULL, 0, TRUE);
	for (c = 0; ruav[c] != NULL; c++)
		dmarcf_dstring_printf(dfc->mctx_histbuf, "rua %s\n", ruav[c]);

	/*
	**  Generate a forensic report.
	*/

	/* XXX -- generate forensic report if requested */

	/*
	**  Enact policy based on DMARC results.
	*/

	switch (policy)
	{
	  case DMARC_POLICY_ABSENT:		/* No DMARC record found */
	  case DMARC_FROM_DOMAIN_ABSENT:	/* No From: domain */
	  case DMARC_POLICY_NONE:		/* Accept and report */
		aresult = "none";
		ret = SMFIS_ACCEPT;
		break;

	  case DMARC_POLICY_PASS:		/* Explicit accept */
		aresult = "pass";
		ret = SMFIS_ACCEPT;
		break;

	  case DMARC_POLICY_REJECT:		/* Explicit reject */
		aresult = "fail";

		if (!conf->conf_deliver)
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
		}

		break;

	  case DMARC_POLICY_QUARANTINE:		/* Explicit quarantine */
		aresult = "fail";

		if (!conf->conf_deliver)
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
		}

		break;

	  default:
		aresult = "temperror";
		ret = SMFIS_TEMPFAIL;
		break;
	}

	/* if the final action isn't TEMPFAIL or REJECT, add an A-R field */
	if (ret != SMFIS_TEMPFAIL && ret != SMFIS_REJECT)
	{
		snprintf(header, sizeof header, "%s; dmarc=%s header.d=%s",
		         conf->conf_authservid, aresult, dfc->mctx_fromdomain);

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

	dmarcf_dstring_printf(dfc->mctx_histbuf, "action %d\n", ret);

	/*
	**  Record activity in the history file.
	*/

	if (conf->conf_historyfile != NULL)
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

		fclose(f);
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
	NULL,		/* SMTP HELO command filter */
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
	fprintf(stderr, "%s: usage: %s [-c conffile] [-V]\n",
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
	char *p;
	char *pidfile = NULL;
	char *testfile = NULL;
	struct config *cfg = NULL;
	char *end;
	char argstr[MAXARGV];
	char err[BUFRSZ + 1];

	/* initialize */
	testmode = FALSE;
	reload = FALSE;
	sock = NULL;
	no_i_whine = TRUE;
	conffile = NULL;

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

		smfilter.xxfi_flags = SMFIF_CHGHDRS|SMFIF_QUARANTINE;
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

	/* perform test mode */
	if (testfile != NULL)
	{
		status = dmarcf_testfiles(testfile, stricttest, verbose);
		return status;
	}

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

	if (curconf->conf_dolog)
	{
		syslog(LOG_INFO, "%s v%s starting (%s)", DMARCF_PRODUCT,
		       VERSION, argstr);
	}

	/* spawn the SIGUSR1 handler */
	status = pthread_create(&rt, NULL, dmarcf_reloader, NULL);
	if (status != 0)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "pthread_create(): %s",
			       strerror(status));

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_OSERR;
		}
	}

	/* call the milter mainline */
	errno = 0;
	status = smfi_main();

	if (curconf->conf_dolog)
	{
		syslog(LOG_INFO,
		       "%s v%s terminating with status %d, errno = %d",
		       DMARCF_PRODUCT, VERSION, status, errno);
	}

	/* tell the reloader thread to die */
	die = TRUE;
	(void) raise(SIGUSR1);

	if (!autorestart && pidfile != NULL)
		(void) unlink(pidfile);

	return status;
}
