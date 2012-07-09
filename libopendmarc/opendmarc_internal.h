/* Copyright (c) 2012, The Trusted Domain Project.  All rights reserved. */

#ifndef OPENDMARC_INTERNAL_H
#define OPENDMARC_INTERNAL_H
#include "build-config.h"

# if HAVE_CTYPE_H
#	include <ctype.h>
# endif
# if HAVE_ERRNO_H
#	include <errno.h>
# endif
# if HAVE_POLL_H
#	include <poll.h>
# endif
# if HAVE_FCNTL_H
#	include <fcntl.h>
# endif
# ifdef sun
#	include <libgen.h>
# endif
# if HAVE_MEMORY_H
#	include <memory.h>
# endif
# if HAVE_STDIO_H
#	 include <stdio.h>
# endif
# if HAVE_STDLIB_H
#	include <stdlib.h>
# endif
# if HAVE_STRING_H
#	include <string.h>
# endif
# if HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
# endif
# if HAVE_SYS_STAT_H
#	include <sys/stat.h>
# endif
# if HAVE_SYS_TYPES_H
#	include <sys/types.h>
# endif
# if HAVE_SYSEXITS_H
#	include <sysexits.h>
# endif
# if HAVE_SYSLOG_H
#	include <syslog.h>
# endif
# if TM_IN_SYS_TIME
#	include <sys/time.h>
# else
#	include <time.h>
# endif
# if TIME_WITH_SYS_TIME && TM_IN_SYS_TIME
#	include <time.h>
# endif
# if HAVE_UNISTD_H
#	include <unistd.h>
# endif
# if HAVE_NETDB_H
#	include <netdb.h>
# endif
# if HAVE_NETINET_IN_H
#	include <netinet/in.h>
# endif
# if HAVE_SYS_PARAM_H
#	include <sys/param.h>
# endif
# if HAVE_ARPA_INET_H
#	include <arpa/inet.h>
# endif
# if HAVE_ARPA_NAMESER_H
#	include <arpa/nameser.h>
# endif
# if HAVE_ARPA_NAMESER_COMPAT_H
#	include <arpa/nameser_compat.h>
# endif
# if HAVE_RESOLV_H
#	include <resolv.h>
# endif
# if HAVE_SIGNAL_H
#	include <signal.h>
# endif
# if HAVE_PTHREAD_H || HAVE_PTHREAD
#	include <pthread.h>
# endif

# ifndef UNDEFINED
#       define UNDEFINED	(-1) 
# endif
# ifndef TRUE
#       define TRUE		(1) 
# endif
# ifndef FALSE 
#       define FALSE		(0)
# endif 
# ifndef MAYBE 
#       define MAYBE		(2)
# endif 
# define bool int
/*
** Beware that some Linux versions incorrectly define 
** MAXHOSTNAMELEN as 64, but DNS lookups require a length
** of 255. So we don't use MAXHOSTNAMELEN here. Instead
** we use our own MAXDNSHOSTNAME.
*/
#define MAXDNSHOSTNAME 256

/*****************************************************************************
** DMARC_POLICY_T -- The opaque context for the library.
** 	Memory needs to be allocated and freed.
*****************************************************************************/

typedef struct dmarc_policy_t {
	/*
	 * Supplied information
	 */
	u_char *	ip_addr;		/* Input: connected IPV4 or IPV6 address */
	int 		ip_type;		/* Input: IPv4 or IPv6 */
	u_char * 	spf_domain;		/* Input: Domain used to verify SPF */
	int 	 	spf_origin;		/* Input: was domain MAIL From: or HELO for SPF check */
	int		spf_outcome;		/* Input: What was the outcome of the SPF check */
	u_char *	spf_human_outcome;	/* Input: What was the outcome of the SPF check in human readable form */
	u_char * 	dkim_domain;		/* Input: The d= domain */
	int		dkim_outcome;		/* Input: What was the outcome of the DKIM check */
	u_char *	dkim_human_outcome;	/* Input: What was the outcome of the DKIM check in human readable form */

	/*
	 * Computed outcomes
	 */
	int		dkim_alignment;
	int		spf_alignment;

	/*
	 * Computed Organizational domain, if subdomain lacked a record.
	 */
	u_char *	from_domain;		/* Input: From: header domain */
	u_char *	organizational_domain;

	/*
	 * Found in the _dmarc record or supplied to us.
	 */
	int		h_error;	/* Zero if found, else DNS error */
	int		adkim;
	int		aspf;
	int		p;
	int		sp;
	int		pct;
	int		rf;
	uint32_t	ri;
	int		rua_cnt;
	u_char **	rua_list;
	int		ruf_cnt;
	u_char **	ruf_list;
} DMARC_POLICY_T;


/* dmarc_dns.c */
char * dmarc_dns_get_record(char *domain, int *reply, char *got_txtbuf, size_t got_txtlen);

/* opendmarc_hash.c */
typedef struct entry_bucket {
	struct entry_bucket *previous;
	struct entry_bucket *next;
	char  *key;
	void  *data;
	time_t timestamp;
} OPENDMARC_HASH_BUCKET;

typedef struct {
	OPENDMARC_HASH_BUCKET   *bucket;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	pthread_mutex_t  mutex;
# endif
} OPENDMARC_HASH_SHELF;

#define	OPENDMARC_MIN_SHELVES_LG2	4
#define	OPENDMARC_MIN_SHELVES	(1 << OPENDMARC_MIN_SHELVES_LG2)

/*
 * max * sizeof internal_entry must fit into size_t.
 * assumes internal_entry is <= 32 (2^5) bytes.
 */
#define	OPENDMARC_MAX_SHELVES_LG2	(sizeof (size_t) * 8 - 1 - 5)
#define	OPENDMARC_MAX_SHELVES	((size_t)1 << OPENDMARC_MAX_SHELVES_LG2)

typedef struct {
	OPENDMARC_HASH_SHELF *table;
	size_t         tablesize;
	void (*freefunct)(void *);
} OPENDMARC_HASH_CTX;

#define OPENDMARC_DEFAULT_HASH_TABLESIZE	(2048)

OPENDMARC_HASH_CTX *	opendmarc_hash_init(size_t tablesize);
OPENDMARC_HASH_CTX *	opendmarc_hash_shutdown(OPENDMARC_HASH_CTX *hctx);
void			opendmarc_hash_set_callback(OPENDMARC_HASH_CTX *hctx, void (*callback)(void *));
void *      		opendmarc_hash_lookup(OPENDMARC_HASH_CTX *hctx, char *string, void *data, size_t datalen);
int           		opendmarc_hash_drop(OPENDMARC_HASH_CTX *hctx, char *string);
int           		opendmarc_hash_expire(OPENDMARC_HASH_CTX *hctx, time_t age);

/* opendmarc_tld.c */
int 			opendmarc_tld_read_file(char *path_fname, char *commentstring, char *drop, char *except);
int 			opendmarc_get_tld(u_char *domain, u_char *tld, size_t tld_len);
int                     opendmarc_reverse_domain(u_char *domain, u_char *buf, size_t buflen);
void 			opendmarc_tld_shutdown();

/* opendmarc_util.c */
u_char ** opendmarc_util_pushargv(u_char *str, u_char **ary, int *cnt);
u_char ** opendmarc_util_clearargv(u_char **ary);
u_char ** opendmarc_util_dupe_argv(u_char **ary);
u_char *  opendmarc_util_cleanup(u_char *str, u_char *buf, size_t buflen);
u_char *  opendmarc_util_finddomain(u_char *raw, u_char *buf, size_t buflen);

/* opendmarc_policy.c */
void opendmarc_policy_library_dns_hook(int *nscountp, struct sockaddr_in *(nsaddr_list[]));

#endif /* OPENDMARC_INTERNAL_H */
