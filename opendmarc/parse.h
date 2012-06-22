/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _DMARCF_MAILPARSE_H_
#define _DMARCF_MAILPARSE_H_

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* prototypes */
extern int dmarcf_mail_parse __P((unsigned char *, unsigned char **,
                                  unsigned char **));

#endif /* ! _DMARCF_MAILPARSE_H_ */
