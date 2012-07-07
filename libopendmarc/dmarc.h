/* Copyright (c) 2012, The Trusted Domain Project.  All rights reserved. */

#ifndef DMARC_H
#define DMARC_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define	OPENDMARC_LIB_VERSION	0x00000000

#define	DMARC_MAXHOSTNAMELEN		(256)

# define DMARC_POLICY_IP_TYPE_IPV4		(4)
# define DMARC_POLICY_IP_TYPE_IPV6		(6)

# define DMARC_POLICY_SPF_ORIGIN_MAILFROM 	(1)
# define DMARC_POLICY_SPF_ORIGIN_HELO		(2)

# define DMARC_POLICY_SPF_OUTCOME_NONE		(0)
# define DMARC_POLICY_SPF_OUTCOME_PASS		(1)
# define DMARC_POLICY_SPF_OUTCOME_FAIL		(2)
# define DMARC_POLICY_SPF_OUTCOME_TMPFAIL 	(3)
# define DMARC_POLICY_SPF_ALIGNMENT_PASS 	(4)
# define DMARC_POLICY_SPF_ALIGNMENT_FAIL 	(5)

# define DMARC_POLICY_DKIM_OUTCOME_NONE		(0)
# define DMARC_POLICY_DKIM_OUTCOME_PASS		(1)
# define DMARC_POLICY_DKIM_OUTCOME_FAIL		(2)
# define DMARC_POLICY_DKIM_OUTCOME_TMPFAIL 	(3)
# define DMARC_POLICY_DKIM_ALIGNMENT_PASS 	(4)
# define DMARC_POLICY_DKIM_ALIGNMENT_FAIL 	(5)

#define DMARC_RECORD_A_UNSPECIFIED	('\0')		/* adkim and aspf */
#define DMARC_RECORD_A_STRICT		('s')		/* adkim and aspf */
#define DMARC_RECORD_A_RELAXED		('r')		/* adkim and aspf */
#define DMARC_RECORD_P_UNSPECIFIED	('\0')		/* p and sp */
#define DMARC_RECORD_P_NONE		('n')		/* p and sp */
#define DMARC_RECORD_P_QUARANTINE	('q')		/* p and sp */
#define DMARC_RECORD_P_REJECT		('r')		/* p and sp */
#define DMARC_RECORD_RF_UNSPECIFIED	(0x0)		/* rf, a bitmap */
#define DMARC_RECORD_RF_AFRF		(0x1)		/* rf, a bitmap */
#define DMARC_RECORD_RF_IODEF		(0x2)		/* rf, a bitmap */

#define DMARC_PARSE_OKAY			(0)	/* Okay to continue */
#define DMARC_PARSE_ERROR_EMPTY			(1)	/* Nothing to parse */
#define DMARC_PARSE_ERROR_NULL_CTX		(2)	/* Got a NULL context */
#define DMARC_PARSE_ERROR_BAD_VERSION		(3)	/* Such as v=DBOB1 */
#define DMARC_PARSE_ERROR_BAD_VALUE		(4)	/* Bad token value like p=bob */
#define DMARC_PARSE_ERROR_NO_REQUIRED_P		(5)	/* Required p= missing */
#define DMARC_PARSE_ERROR_NO_DOMAIN		(6)	/* No domain, e.g. <>  */
#define DMARC_PARSE_ERROR_NO_ALLOC		(7)	/* Memory Allocation Faliure */
#define DMARC_PARSE_ERROR_BAD_SPF_MACRO		(8)	/* Was not a macro from above */
#define DMARC_PARSE_ERROR_BAD_DKIM_MACRO	DMARC_PARSE_ERROR_BAD_SPF_MACRO
#define DMARC_DNS_ERROR_NO_RECORD		(9)	/* No DMARC record was found */
#define DMARC_DNS_ERROR_NXDOMAIN		(10)	/* No such domain exists */
#define DMARC_DNS_ERROR_TMPERR			(11)	/* Recoveralble DNS error */
#define DMARC_TLD_ERROR_UNKNOWN			(12)	/* Undefined TLD type    */
#define DMARC_FROM_DOMAIN_ABSENT		(13)	/* Undefined TLD type    */

#define DMARC_POLICY_ABSENT			(14)	/* Policy OK so accept message */
#define DMARC_POLICY_PASS			(15)	/* Policy OK so accept message */
#define DMARC_POLICY_REJECT			(16)	/* Policy says to reject message */
#define DMARC_POLICY_QUARANTINE			(17)	/* Policy says to quarantine message */
#define DMARC_POLICY_NONE			(18)	/* Policy says to monitor and report */

#ifndef OPENDMARC_POLICY_C
 typedef struct dmarc_policy_t DMARC_POLICY_T;
#endif

#define OPENDMARC_STATUS_T int

#ifndef MAXPATHLEN
# define MAXPATHLEN (2048)
#endif
#ifndef MAXNS
# define MAXNS (3)
#endif
#define OPENDMARC_MAX_NSADDRLIST (8)
typedef struct {
	int			tld_type;
	u_char 			tld_source_file[MAXPATHLEN];
	int    			nscount;
	struct sockaddr_in 	nsaddr_list[MAXNS];
} OPENDMARC_LIB_T;

#define OPENDMARC_TLD_TYPE_NONE    (0)	/* Will not use a tld file             */
#define OPENDMARC_TLD_TYPE_MOZILLA (1)	/* mozilla.org effective_tld_names.dat */
               
/*
 * Library one time initialization.
 */
OPENDMARC_STATUS_T  opendmarc_policy_library_init(OPENDMARC_LIB_T *lib_init);
OPENDMARC_STATUS_T  opendmarc_policy_library_shutdown(OPENDMARC_LIB_T *lib_init);

/*
 * Context management.
 */
DMARC_POLICY_T * opendmarc_policy_connect_init(u_char *ip_addr, int ip_type);
DMARC_POLICY_T * opendmarc_policy_connect_clear(DMARC_POLICY_T *pctx);
DMARC_POLICY_T * opendmarc_policy_connect_rset(DMARC_POLICY_T *pctx);
DMARC_POLICY_T * opendmarc_policy_connect_shutdown(DMARC_POLICY_T *pctx);

/*
 * Store information routines.
 */
OPENDMARC_STATUS_T opendmarc_policy_store_from_domain(DMARC_POLICY_T *pctx, u_char *domain);
OPENDMARC_STATUS_T opendmarc_policy_store_dkim(DMARC_POLICY_T *pctx, u_char *domain, int result, u_char *human_result);
OPENDMARC_STATUS_T opendmarc_policy_store_spf(DMARC_POLICY_T *pctx, u_char *domain, int result, int origin, u_char *human_result);

/*
 * The DMARC record itself.
 */
OPENDMARC_STATUS_T opendmarc_policy_query_dmarc(DMARC_POLICY_T *pctx, u_char *domain);
OPENDMARC_STATUS_T opendmarc_policy_parse_dmarc(DMARC_POLICY_T *pctx, u_char *domain, u_char *record);
OPENDMARC_STATUS_T opendmarc_policy_store_dmarc(DMARC_POLICY_T *pctx, u_char *dmarc_record, u_char *domain, u_char *organizationaldomain);

/*
 * Access to parts of the DMARC record.
 */
OPENDMARC_STATUS_T opendmarc_get_policy_to_enforce(DMARC_POLICY_T *pctx);
OPENDMARC_STATUS_T opendmarc_policy_fetch_alignment(DMARC_POLICY_T *pctx, int *dkim_alignment, int *spf_alignment);
OPENDMARC_STATUS_T opendmarc_policy_fetch_pct(DMARC_POLICY_T *pctx, int *pctp);
OPENDMARC_STATUS_T opendmarc_policy_fetch_adkim(DMARC_POLICY_T *pctx, int *adkim);
OPENDMARC_STATUS_T opendmarc_policy_fetch_aspf(DMARC_POLICY_T *pctx, int *aspf);
OPENDMARC_STATUS_T opendmarc_policy_fetch_p(DMARC_POLICY_T *pctx, int *p);
OPENDMARC_STATUS_T opendmarc_policy_fetch_sp(DMARC_POLICY_T *pctx, int *sp);
u_char **	   opendmarc_policy_fetch_rua(DMARC_POLICY_T *pctx, u_char *list_buf, size_t size_of_buf, int constant);
u_char **	   opendmarc_policy_fetch_ruf(DMARC_POLICY_T *pctx, u_char *list_buf, size_t size_of_buf, int constant);
OPENDMARC_STATUS_T opendmarc_policy_fetch_utilized_domain(DMARC_POLICY_T *pctx, u_char *buf, size_t buflen);
OPENDMARC_STATUS_T opendmarc_policy_fetch_alignment(DMARC_POLICY_T *pctx, int *dkim_alignment, int *spf_alignment);

/*
 * TLD processing
 */
int opendmarc_tld_read_file(char *path_fname, char *commentstring, char *drop, char *except);

#endif /* DMARC_H */
