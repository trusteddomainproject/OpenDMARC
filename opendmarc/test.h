/*
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _TEST_H_
#define _TEST_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libmilter includes */
#include <libmilter/mfapi.h>

/* libopendmarc includes */
#include "dmarc.h"

/* PROTOTYPES */
extern int dmarcf_testfiles __P((char *, bool, int));

extern int dmarcf_test_addheader __P((void *, char *, char *));
extern int dmarcf_test_addrcpt __P((void *, char *));
extern int dmarcf_test_chgheader __P((void *, char *, int, char *));
extern int dmarcf_test_delrcpt __P((void *, char *));
extern void *dmarcf_test_getpriv __P((void *));
extern char *dmarcf_test_getsymval __P((void *, char *));
extern int dmarcf_test_insheader __P((void *, int, char *, char *));
extern int dmarcf_test_progress __P((void *));
extern int dmarcf_test_quarantine __P((void *, char *));
extern int dmarcf_test_setpriv __P((void *, void *));
extern int dmarcf_test_setreply __P((void *, char *, char *, char *));

#endif /* _TEST_H_ */
