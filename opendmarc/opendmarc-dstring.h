/*
**  Copyright (c) 2004, 2005, 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.
**  	All rights reserved.
*/

#ifndef _DSTRING_H_
#define _DSTRING_H_

/* system includes */
#include <sys/types.h>

/* TYPES */
struct dmarcf_dstring;

/* PROTOTYPES */
extern struct dmarcf_dstring *dmarcf_dstring_new __P((int, int));
extern void dmarcf_dstring_free __P((struct dmarcf_dstring *));
extern _Bool dmarcf_dstring_copy __P((struct dmarcf_dstring *, u_char *));
extern _Bool dmarcf_dstring_cat __P((struct dmarcf_dstring *, u_char *));
extern _Bool dmarcf_dstring_cat1 __P((struct dmarcf_dstring *, int));
extern _Bool dmarcf_dstring_catn __P((struct dmarcf_dstring *, u_char *, size_t));
extern void dmarcf_dstring_chop __P((struct dmarcf_dstring *, int));
extern u_char *dmarcf_dstring_get __P((struct dmarcf_dstring *));
extern int dmarcf_dstring_len __P((struct dmarcf_dstring *));
extern void dmarcf_dstring_blank __P((struct dmarcf_dstring *));
extern size_t dmarcf_dstring_printf __P((struct dmarcf_dstring *, char *, ...));

#endif /* _DSTRING_H_ */
