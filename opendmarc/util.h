/*
**  Copyright (c) 2012, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

/* system includes */
#include <sys/types.h>
#include <stdio.h>

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* PROTOTYPES */
extern void dmarcf_optlist __P((FILE *));
extern void dmarcf_setmaxfd __P((void));
extern int dmarcf_socket_cleanup __P((char *));

#endif /* _UTIL_H_ */
