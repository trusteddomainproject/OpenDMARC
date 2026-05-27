/*
**  Copyright (c) 2025, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _OPENDMARC_SPF_PARSE_H_
#define _OPENDMARC_SPF_PARSE_H_

/*
**  Buffer sizes — match the values in opendmarc.h/opendmarc-ar.h so this
**  header can be used from test code that cannot include the milter headers.
*/
#ifndef BUFRSZ
# define BUFRSZ			2048
#endif
#ifndef MAXSPFRESULT
# define MAXSPFRESULT		16
#endif

/*
**  ARES_RESULT_* constants — duplicated here with guards so test code can
**  use this header standalone without pulling in opendmarc-ar.h (which
**  depends on libmilter headers).
*/
#ifndef FALSE
# define FALSE	0
# define TRUE	1
#endif /* !FALSE */

#ifndef ARES_RESULT_UNDEFINED
# define ARES_RESULT_UNDEFINED	(-1)
# define ARES_RESULT_PASS	0
# define ARES_RESULT_SOFTFAIL	2
# define ARES_RESULT_NEUTRAL	3
# define ARES_RESULT_TEMPERROR	4
# define ARES_RESULT_PERMERROR	5
# define ARES_RESULT_NONE	6
# define ARES_RESULT_FAIL	7
#endif /* !ARES_RESULT_UNDEFINED */

extern int dmarcf_parse_received_spf(char *str, char *envdomain);

#endif /* _OPENDMARC_SPF_PARSE_H_ */
