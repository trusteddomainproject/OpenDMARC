/* Copyright (c) 2012, The Trusted Domain Project.  All rights reserved. */

#ifndef LIBOPENDMARC_H
#define LIBOPENDMARC_H

# define DMARC_POLICY_IP_TYPE_IPV4	(4)
# define DMARC_POLICY_IP_TYPE_IPV6	(6)

# define DMARC_POLICY_SPF_ORIGIN_MAILFROM (1)
# define DMARC_POLICY_SPF_ORIGIN_HELO	(2)

# define DMARC_POLICY_SPF_OUTCOME_NONE	(0)
# define DMARC_POLICY_SPF_OUTCOME_PASS	(1)
# define DMARC_POLICY_SPF_OUTCOME_FAIL	(2)
# define DMARC_POLICY_SPF_OUTCOME_TMPFAIL (3)

#define DMARC_RECORD_A_UNSPECIFIED	('\0')		/* adkim and aspf */
#define DMARC_RECORD_A_STRICT		('s')		/* adkim and aspf */
#define DMARC_RECORD_A_RELAXED		('r')		/* adkim and aspf */
#define DMARC_RECORD_P_UNSPECIFIED	('\0')		/* p and sp */
#define DMARC_RECORD_P_NONE		('n')		/* p and sp */
#define DMARC_RECORD_P_QUARANTINE	('q')		/* p and sp */
#define DMARC_RECORD_P_REJECT		('r')		/* p and sp */
#define DMARC_RECORD_R_UNSPECIFIED	(0x0)		/* rf, a bitmap */
#define DMARC_RECORD_R_AFRF		(0x1)		/* rf, a bitmap */
#define DMARC_RECORD_R_IODEF		(0x2)		/* rf, a bitmap */

#define DMARC_PARSE_ERROR_EMPTY		(1)		/* Nothing to parse */
#define DMARC_PARSE_ERROR_BAD_VERSION	(2)		/* Such as v=DBOB1 */
#define DMARC_PARSE_ERROR_BAD_VALUE	(3)		/* Bad token value like p=bob */
#define DMARC_PARSE_ERROR_NO_REQUIRED_P	(4)		/* Required p= missing */

#ifndef OPENDMARC_POLICY_C
 typedef struct dmarc_policy_t DMARC_POLICY_T;
#endif

DMARC_POLICY_T * opendmarc_policy_connect_init(u_char *ip_addr, int ip_type);
DMARC_POLICY_T * opendmarc_policy_connect_shutdown(DMARC_POLICY_T *pctx);


#endif /* LIBOPENDMARC_H */
