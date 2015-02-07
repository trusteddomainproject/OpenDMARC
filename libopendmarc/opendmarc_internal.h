/* Copyright (c) 2012-2015, The Trusted Domain Project.  All rights reserved. */

#ifndef OPENDMARC_INTERNAL_H
#define OPENDMARC_INTERNAL_H

#if HAVE_CONFIG_H
# include "build-config.h"
#endif

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

/*
** Maximum number of DNS retries when resolving CNAMES, etc.
*/

#define	DNS_MAX_RETRIES 6

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
	int		dkim_final;		/* This is the best record found */
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
	int		fo;
} DMARC_POLICY_T;
#ifndef OPENDMARC_POLICY_C
# define OPENDMARC_POLICY_C 1
#endif /* ! OPENDMARC_POLICY_C */


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
char **   opendmarc_util_freenargv(char **ary, int *num);
char **   opendmarc_util_pushnargv(char *str, char **ary, int *num);
char *    opendmarc_util_ultoa(unsigned long val, char *buffer, size_t bufferlen);

/* opendmarc_policy.c */
void opendmarc_policy_library_dns_hook(int *nscountp, struct sockaddr_in *nsaddr_list);

#if WITH_SPF

#if HAVE_SPF2_H
#define HAVE_NS_TYPE
#include "spf.h"
typedef struct spf_context_struct { 
	SPF_server_t *		spf_server;
	SPF_request_t *		spf_request;
	SPF_response_t *	spf_response;
	SPF_result_t		spf_result;
	char    		mailfrom_addr[512];
	char			mailfrom_domain[256];
	char    		helo_domain[256];
} SPF_CTX_T;
int opendmarc_spf2_test(char *ip_address, char *mail_from_domain, char *helo_domain, char *spf_record, int softfail_okay_flag, char *human_readable, size_t human_readable_len, int *used_mfrom);

#else /* not HAVE_SPF2_H */

/* opendmarc_spf.c and opendmarc_spf_dns.c */
#define MAX_SPF_RECURSION (10)
typedef struct spf_context_struct { 
        int     nlines;
	char *  lines[MAX_SPF_RECURSION+2];
	int     status;
	int     in_token;
	char    mailfrom_addr[512];
	char    helo_domain[256];
	char    mailfrom_domain[256];
	char    validated_domain[256];
	char    ip_address[32];
	char    spf_record[BUFSIZ *2];
	char ** iplist;
	int     ipcount;
	char    exp_buf[512];
	int     did_get_exp;
} SPF_CTX_T;
int		opendmarc_spf_test(char *ip_address, char *mail_from_domain, char *helo_domain, char *spf_record, int softfail_okay_flag, char *human_readable, size_t human_readable_len, int *used_mfrom);
char ** 	opendmarc_spf_dns_lookup_a(char *domain, char **ary, int *cnt);
char ** 	opendmarc_spf_dns_lookup_mx(char *domain, char **ary, int *cnt);
char ** 	opendmarc_spf_dns_lookup_mx_domain(char *domain, char **ary, int *cnt);
char ** 	opendmarc_spf_dns_lookup_ptr(char *ip, char **ary, int *cnt);
int     	opendmarc_spf_dns_cidr_address(char *addr, u_long *hi, u_long *lo);
int     	opendmarc_spf_dns_does_domain_exist(char *domain, int *reply);
char *  	opendmarc_spf_dns_get_record(char *domain, int *reply, char *txt, size_t txtlen, char *cname, size_t cnamelen, int spfcheck);
int     	opendmarc_spf_dns_does_domain_exist(char *domain, int *reply);
char *  	opendmarc_spf_dns_get_record(char *domain, int *reply, char *txt, size_t txtlen, char *cname, size_t cnamelen, int spfcheck);
int 		opendmarc_spf_ipv6_cidr_check(char *ipv6_str, char *cidr_string);
int 		opendmarc_spf_cidr_address(u_long ip, char *cidr_addr);
SPF_CTX_T *     opendmarc_spf_alloc_ctx();
SPF_CTX_T *     opendmarc_spf_free_ctx(SPF_CTX_T *spfctx);
int             opendmarc_spf_status_to_pass(int status, int none_pass);
int             opendmarc_spf_specify_mailfrom(SPF_CTX_T *spfctx, char *mailfrom, size_t mailfrom_len, int *use_domain);
int             opendmarc_spf_specify_helo_domain(SPF_CTX_T *spfctx, char *helo_domain, size_t helo_domain_len);
int             opendmarc_spf_specify_ip_address(SPF_CTX_T *spfctx, char *ip_address, size_t ip_address_len);
int             opendmarc_spf_specify_record(SPF_CTX_T *spfctx, char *spf_record, size_t spf_record_length);
int             opendmarc_spf_parse(SPF_CTX_T *spfctx, int dns_count, char *xbuf, size_t xbuf_len);
const char *    opendmarc_spf_status_to_msg(SPF_CTX_T *spfctx, int status);
#endif /* HAVE_SPF2_H */

#endif /* WITH_SPF */

#endif /* OPENDMARC_INTERNAL_H */
