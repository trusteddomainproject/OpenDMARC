/* Copyright (c) 2012, The Trusted Domain Project.  All rights reserved. */

#ifndef DMARC_H
#define DMARC_H

#define	DMARC_MAXHOSTNAMELEN		(256)

# define DMARC_POLICY_IP_TYPE_IPV4		(4)
# define DMARC_POLICY_IP_TYPE_IPV6		(6)

# define DMARC_POLICY_SPF_ORIGIN_MAILFROM 	(1)
# define DMARC_POLICY_SPF_ORIGIN_HELO		(2)

# define DMARC_POLICY_SPF_OUTCOME_NONE		(0)
# define DMARC_POLICY_SPF_OUTCOME_PASS		(1)
# define DMARC_POLICY_SPF_OUTCOME_FAIL		(2)
# define DMARC_POLICY_SPF_OUTCOME_TMPFAIL 	(3)

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

#define DMARC_PARSE_OKAY			(0)	/* Nothing to parse */
#define DMARC_PARSE_ERROR_EMPTY			(1)	/* Nothing to parse */
#define DMARC_PARSE_ERROR_NULL_CTX		(2)	/* Got a NULL context */
#define DMARC_PARSE_ERROR_BAD_VERSION		(3)	/* Such as v=DBOB1 */
#define DMARC_PARSE_ERROR_BAD_VALUE		(4)	/* Bad token value like p=bob */
#define DMARC_PARSE_ERROR_NO_REQUIRED_P		(5)	/* Required p= missing */
#define DMARC_PARSE_ERROR_NO_DOMAIN		(6)	/* No domain, e.g. <>  */
#define DMARC_PARSE_ERROR_NO_ALLOC		(7)	/* Memory Allocation Faliure */
#define DMARC_PARSE_ERROR_BAD_SPF_MACRO		(8)	/* Was not a macro from above */
#define DMARC_DNS_ERROR_NO_RECORD		(9)	/* No DMARC record was found */
#define DMARC_DNS_ERROR_NXDOMAIN		(10)	/* No such domain exists */
#define DMARC_DNS_ERROR_TMPERR			(11)	/* Recoveralble DNS error */

#ifndef OPENDMARC_POLICY_C
 typedef struct dmarc_policy_t DMARC_POLICY_T;
#endif

#define OPENDMARC_STATUS_T int

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

OPENDMARC_STATUS_T opendmarc_policy_store_dkim(DMARC_POLICY_T *pctx, u_char *domain, u_char *result, u_char *human_result);
OPENDMARC_STATUS_T opendmarc_policy_store_from_domain(DMARC_POLICY_T *pctx, u_char *domain);
OPENDMARC_STATUS_T opendmarc_policy_store_spf(DMARC_POLICY_T *pctx, u_char *domain, int result, int origin, u_char *human_result);

/*
 * The DMARC record itself.
 */

OPENDMARC_STATUS_T opendmarc_parse_dmarc(DMARC_POLICY_T *pctx, u_char *record);

/*
 * Access to parts of the DMARC record.
 */

int opendmarc_get_policy_to_enforce(DMARC_POLICY_T *pctx);

#endif /* DMARC_H */
