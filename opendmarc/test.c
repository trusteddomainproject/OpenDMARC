/*
**  Copyright (c) 2012, 2014-2016, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sysexits.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <netdb.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendmarc_strl if needed */
#ifdef USE_DMARCSTRL_H
# include <opendmarc_strl.h>
#endif /* USE_DMARCSTRL_H */

/* libmilter includes */
#include <libmilter/mfapi.h>

/* opendmarc includes */
#include "test.h"
#include "opendmarc.h"

/* local types and definitions*/
#define	CRLF		"\r\n"

struct test_context
{
	void *	tc_priv;		/* private data pointer */
};

char *milter_status[] =
{
	"SMFIS_CONTINUE",
	"SMFIS_REJECT",
	"SMFIS_DISCARD",
	"SMFIS_ACCEPT",
	"SMFIS_TEMPFAIL"
};

#define	FCLOSE(x)		if ((x) != stdin) \
					fclose((x));
#define	MLFI_OUTPUT(x,y)	((y) > 1 || ((y) == 1 && (x) != SMFIS_CONTINUE))
#define	STRORNULL(x)		((x) == NULL ? "(null)" : (x))

/* globals */
static int tverbose = 0;

/*
**  DMARCF_TEST_ENVCHECK -- get environment variable or use default
**
**  Parameters:
**  	evname -- environment variable name
**  	dflt -- default to apply
**
**  Return value:
**  	Value of "evname" if set, otherwise "default".
*/

static char *
dmarcf_test_envcheck(char *evname, char *dflt)
{
	char *v;

	v = getenv(evname);
	return (v == NULL ? dflt : v);
}

/*
**  DMARCF_TEST_SETPRIV -- store private pointer
**
**  Parameters:
**  	ctx -- context pointer
**  	ptr -- pointer to store
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_setpriv(void *ctx, void *ptr)
{
	struct test_context *tc;

	assert(ctx != NULL);

	tc = ctx;
	tc->tc_priv = ptr;

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_GETPRIV -- retrieve private pointer
**
**  Parameters:
**  	ctx -- context pointer
**
**  Return value:
**  	The private pointer.
*/

void *
dmarcf_test_getpriv(void *ctx)
{
	struct test_context *tc;

	assert(ctx != NULL);

	tc = ctx;

	return tc->tc_priv;
}

/*
**  DMARCF_TEST_PROGRESS -- send progress message
**
**  Parameters:
**  	ctx -- context pointer
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_progress(void *ctx)
{
	assert(ctx != NULL);

	if (tverbose > 1)
		fprintf(stdout, "### PROGRESS\n");

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_SETREPLY -- set reply to use
**
**  Parameters:
**  	ctx -- context pointer
**  	rcode -- SMTP reply code
**  	xcode -- SMTP enhanced reply code
**  	replytxt -- SMTP reply text
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_setreply(void *ctx, char *rcode, char *xcode, char *replytxt)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### SETREPLY: rcode='%s' xcode='%s' replytxt='%s'\n",
		        STRORNULL(rcode), STRORNULL(xcode),
		        STRORNULL(replytxt));
	}

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_INSHEADER -- insert a header
**
**  Parameters:
**  	ctx -- context pointer
**  	idx -- insertion index
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_insheader(void *ctx, int idx, char *hname, char *hvalue)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### INSHEADER: idx=%d hname='%s' hvalue='%s'\n",
		        idx, STRORNULL(hname), STRORNULL(hvalue));
	}

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_CHGHEADER -- change a header
**
**  Parameters:
**  	ctx -- context pointer
**  	hname -- header name
**  	idx -- header index
**  	hvalue -- header value
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_chgheader(void *ctx, char *hname, int idx, char *hvalue)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### CHGHEADER: hname='%s' idx=%d hvalue='%s'\n",
		        STRORNULL(hname), idx, STRORNULL(hvalue));
	}

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_QUARANTINE -- request message quarantine
**
**  Parameters:
**  	ctx -- context pointer
**  	reason -- reason string
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_quarantine(void *ctx, char *reason)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### QUARANTINE: reason='%s'\n", STRORNULL(reason));
	}

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_ADDHEADER -- append a header
**
**  Parameters:
**  	ctx -- context pointer
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_addheader(void *ctx, char *hname, char *hvalue)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### ADDHEADER: hname='%s' hvalue='%s'\n",
		        STRORNULL(hname), STRORNULL(hvalue));
	}

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_DELRCPT -- request recipient delete
**
**  Parameters:
**  	ctx -- context pointer
**  	addr -- address
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_delrcpt(void *ctx, char *addr)
{
	assert(ctx != NULL);
	assert(addr != NULL);

	if (tverbose > 1)
		fprintf(stdout, "### DELRCPT: '%s'\n", addr);

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_ADDRCPT -- request recipient add
**
**  Parameters:
**  	ctx -- context pointer
**  	addr -- address
**
**  Return value:
**  	MI_SUCCESS
*/

int
dmarcf_test_addrcpt(void *ctx, char *addr)
{
	assert(ctx != NULL);
	assert(addr != NULL);

	if (tverbose > 1)
		fprintf(stdout, "### ADDRCPT: '%s'\n", addr);

	return MI_SUCCESS;
}

/*
**  DMARCF_TEST_GETSYMVAL -- retrieve a symbol value
**
**  Parameters:
**  	ctx -- context pointer
**  	sym -- symbol name
**
**  Return value:
**  	Pointer to (static) string name.
**
**  Note:
**  	This isn't thread-safe, but test mode is single-threaded anyway.
**  	This is also a memory leak, but it's a short-lived test program
**  	anyway.
*/

char *
dmarcf_test_getsymval(void *ctx, char *sym)
{
	static char symout[BUFRSZ];

	assert(ctx != NULL);
	assert(sym != NULL);

	snprintf(symout, sizeof symout, "DEBUG-%s", sym);

	return strdup(symout);
}

/*
**  DMARCF_TESTFILE -- read a message and test it
**
**  Parameters:
**  	tctx -- test context handle
**  	file -- input file path
**  	strict -- strict CRLF mode?
**  	verbose -- verbose level
**
**  Return value:
**  	An EX_* constant (see sysexits.h)
*/

static int
dmarcf_testfile(struct test_context *tctx, FILE *f, char *file,
                _Bool strict, int tverbose)
{
	bool inheaders = TRUE;
	int lineno = 0;
	int hslineno = 0;
	int c;
	char *p;
	sfsistat ms;
	char buf[BUFRSZ];
	char line[BUFRSZ];
	char *envfrom[2];

	assert(tctx != NULL);
	assert(f != NULL);

	memset(buf, '\0', sizeof buf);
	memset(line, '\0', sizeof buf);

	envfrom[0] = dmarcf_test_envcheck("OPENDMARC_TEST_ENVFROM",
	                                  "<sender@example.org>");
	envfrom[1] = NULL;

	ms = mlfi_envfrom((SMFICTX *) tctx, envfrom);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: %s: mlfi_envfrom() returned %s\n",
		        progname, file, milter_status[ms]);
	}
	if (ms != SMFIS_CONTINUE)
		return EX_SOFTWARE;

	while (!feof(f))
	{
		if (fgets(line, sizeof line, f) == NULL)
			break;

		lineno++;

		c = '\0';
		for (p = line; *p != '\0'; p++)
		{
			if (*p == '\n')
			{
				*p = '\0';
				break;
			}

			c = *p;
		}

		if (c != '\r')
		{
			if (strict)			/* error */
			{
				fprintf(stderr,
				        "%s: %s: line %d: not CRLF-terminated\n",
				        progname, file, lineno);
				return EX_DATAERR;
			}
		}
		else if (p != line)			/* eat the CR */
		{
			*(p - 1) = '\0';
		}

		if (inheaders)
		{
			if (line[0] == '\0')
			{
				if (buf[0] != '\0')
				{
					char *colon;

					colon = strchr(buf, ':');
					if (colon == NULL)
					{
						fprintf(stderr,
						        "%s: %s: line %d: header malformed\n",
						        progname, file,
						        lineno);
						return EX_DATAERR;
					}

					*colon = '\0';
					if (*(colon + 1) == ' ')
						colon++;

					ms = mlfi_header((SMFICTX *) tctx, buf,
					                 colon + 1);
					if (MLFI_OUTPUT(ms, tverbose))
					{
						fprintf(stderr,
						        "%s: %s: line %d: mlfi_header() returned %s\n",
						         progname, file,
						         hslineno,
						         milter_status[ms]);
					}

					if (ms != SMFIS_CONTINUE)
						return EX_SOFTWARE;
				}

				inheaders = FALSE;
				memset(buf, '\0', sizeof buf);
				memset(line, '\0', sizeof buf);

				continue;
			}

			if (line[0] == ' ' || line[0] == '\t')
			{
				(void) strlcat(buf, CRLF, sizeof buf);

				if (strlcat(buf, line,
				            sizeof buf) >= sizeof buf)
				{
					fprintf(stderr,
					        "%s: %s: line %d: header '%*s...' too large\n",
					        progname, file, lineno,
					        20, buf);
					return EX_DATAERR;
				}
			}
			else
			{
				if (buf[0] != '\0')
				{
					char *colon;

					colon = strchr(buf, ':');
					if (colon == NULL)
					{
						fprintf(stderr,
						        "%s: %s: line %d: header malformed\n",
						        progname, file,
						        lineno);
						return EX_DATAERR;
					}

					*colon = '\0';
					if (*(colon + 1) == ' ')
						colon++;

					ms = mlfi_header((SMFICTX *) tctx, buf,
					                 colon + 1);
					if (MLFI_OUTPUT(ms, tverbose))
					{
						fprintf(stderr,
						        "%s: %s: line %d: mlfi_header() returned %s\n",
						        progname, file,
						        hslineno,
						        milter_status[ms]);
					}
					if (ms != SMFIS_CONTINUE)
						return EX_SOFTWARE;
					hslineno = 0;
				}

				if (hslineno == 0)
					hslineno = lineno;

				strlcpy(buf, line, sizeof buf);
			}
		}
	}

	/* unprocessed partial header? */
	if (inheaders && buf[0] != '\0')
	{
		char *colon;

		colon = strchr(buf, ':');
		if (colon == NULL)
		{
			fprintf(stderr,
			        "%s: %s: line %d: header malformed\n",
			        progname, file, lineno);
			return EX_DATAERR;
		}

		*colon = '\0';
		if (*(colon + 1) == ' ')
			colon++;

		ms = mlfi_header((SMFICTX *) tctx, buf, colon + 1);
		if (MLFI_OUTPUT(ms, tverbose))
		{
			fprintf(stderr,
			        "%s: %s: line %d: mlfi_header() returned %s\n",
			        progname, file, lineno, milter_status[ms]);
		}
		if (ms != SMFIS_CONTINUE)
			return EX_SOFTWARE;

		inheaders = FALSE;
		memset(buf, '\0', sizeof buf);
	}

	/* no headers found */
	if (inheaders)
	{
		fprintf(stderr, "%s: %s: warning: no headers on input\n",
		        progname, file);
	}

	ms = mlfi_eom((SMFICTX *) tctx);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: %s: mlfi_eom() returned %s\n",
		        progname, file, milter_status[ms]);
	}

	return EX_OK;
}

/*
**  DMARCF_TESTFILES -- test one or more input messages
**
**  Parameters:
**  	flist -- input file list
**  	strict -- strict CRLF mode?
**  	verbose -- verbose level
**
**  Return value:
**  	An EX_* constant (see sysexits.h)
*/

int
dmarcf_testfiles(char *flist, bool strict, int verbose)
{
	char *file;
	char *ctx;
	char *addr;
	FILE *f;
	int status;
	int retval;
	sfsistat ms;
	struct test_context *tctx;
	struct sockaddr_in sin;
	struct addrinfo *ain;

	assert(flist != NULL);

	tverbose = verbose;

	/* set up a fake SMFICTX */
	tctx = (struct test_context *) malloc(sizeof(struct test_context));
	if (tctx == NULL)
	{
		fprintf(stderr, "%s: malloc(): %s\n", progname,
		        strerror(errno));
		return EX_OSERR;
	}
	tctx->tc_priv = NULL;

	(void) memset(&sin, '\0', sizeof sin);

	addr = dmarcf_test_envcheck("OPENDMARC_TEST_CLIENTIP", NULL);

	if (addr == NULL)
	{
		retval = getaddrinfo("127.0.0.1", NULL, NULL, &ain);
	}
	else
	{
		retval = getaddrinfo(addr, NULL, NULL, &ain);
	}

	if (retval != 0)
	{
		fprintf(stderr, "%s: getaddrinfo: %s\n", progname,
			gai_strerror(retval));
		return EX_NOHOST;
	}

	ms = mlfi_connect((SMFICTX *) tctx,
	                  dmarcf_test_envcheck("OPENDMARC_TEST_CLIENTHOST",
                                               "localhost"),
                          ain->ai_addr);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: mlfi_connect() returned %s\n",
		        progname, milter_status[ms]);
	}
	if (ms != SMFIS_CONTINUE)
		return EX_SOFTWARE;

#ifdef WITH_SPF
	ms = mlfi_helo((SMFICTX *) tctx,
	               dmarcf_test_envcheck("OPENDMARC_TEST_HELOHOST",
                                            "localhost"));
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: mlfi_helo() returned %s\n",
		        progname, milter_status[ms]);
	}
	if (ms != SMFIS_CONTINUE)
		return EX_SOFTWARE;
#endif /* WITH_SPF */

	/* loop through inputs */
	for (file = strtok_r(flist, ",", &ctx);
	     file != NULL;
	     file = strtok_r(NULL, ",", &ctx))
	{
		/* open the input */
		if (strcmp(file, "-") == 0)
		{
			f = stdin;
			file = "(stdin)";
		}
		else
		{
			f = fopen(file, "r");
			if (f == NULL)
			{
				fprintf(stderr, "%s: %s: fopen(): %s\n",
				        progname, file, strerror(errno));
				return EX_UNAVAILABLE;
			}
		}

		status = dmarcf_testfile(tctx, f, file, strict, tverbose);

		FCLOSE(f);

		if (status != EX_OK)
			return status;
	}

	ms = mlfi_close((SMFICTX *) tctx);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: mlfi_close() returned %s\n",
		        progname, milter_status[ms]);
	}

	return EX_OK;
}
