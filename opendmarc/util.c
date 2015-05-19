/*
**  Copyright (c) 2009-2012, 2014, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif /* HAVE_PATHS_H */
#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif /* ! _PATH_DEVNULL */

#ifdef SOLARIS
# if SOLARIS <= 20600
#  define socklen_t size_t
# endif /* SOLARIS <= 20600 */
#endif /* SOLARIS */

#ifndef FALSE
# define FALSE 0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE 1
#endif /* ! TRUE */

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

/* opendmarc includes */
#include "util.h"

static char *optlist[] =
{
#if DEBUG
	"DEBUG",
#endif /* DEBUG */

#if POLL
	"POLL",
#endif /* POLL */

#if WITH_SPF
	"WITH_SPF",
#endif /* WITH_SPF */

#if HAVE_SPF2_H
	"WITH_SPF2",
#endif /* HAVE_SPF2_H */

	NULL
};

/*
**  DMARCF_OPTLIST -- print active options and FFRs
**
**  Parameters:
**  	where -- where to write the list
**
**  Return value:
**   	None.
*/

void
dmarcf_optlist(FILE *where)
{
	_Bool first = TRUE;
	int c;

	assert(where != NULL);

	for (c = 0; optlist[c] != NULL; c++)
	{
		if (first)
		{
			fprintf(where, "\tActive code options:\n");
			first = FALSE;
		}

		fprintf(where, "\t\t%s\n", optlist[c]);
	}
}

/*
**  DMARCF_SETMAXFD -- increase the file descriptor limit as much as possible
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
dmarcf_setmaxfd(void)
{
	struct rlimit rlp;

	if (getrlimit(RLIMIT_NOFILE, &rlp) != 0)
	{
		syslog(LOG_WARNING, "getrlimit(): %s", strerror(errno));
	}
	else
	{
		rlp.rlim_cur = rlp.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rlp) != 0)
		{
			syslog(LOG_WARNING, "setrlimit(): %s",
			       strerror(errno));
		}
	}
}

/*
**  DMARCF_SOCKET_CLEANUP -- try to clean up the socket
**
**  Parameters:
**  	sockspec -- socket specification
**
**  Return value:
**  	0 -- nothing to cleanup or cleanup successful
**  	other -- an error code (a la errno)
*/

int
dmarcf_socket_cleanup(char *sockspec)
{
	int s;
	char *colon;
	struct sockaddr_un sock;

	assert(sockspec != NULL);

	/* we only care about "local" or "unix" sockets */
	colon = strchr(sockspec, ':');
	if (colon != NULL)
	{
		if (strncasecmp(sockspec, "local:", 6) != 0 &&
		    strncasecmp(sockspec, "unix:", 5) != 0)
			return 0;
	}

	/* find the filename */
	if (colon == NULL)
	{
		colon = sockspec;
	}
	else
	{
		if (*(colon + 1) == '\0')
			return EINVAL;
	}

	/* get a socket */
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s == -1)
		return errno;

	/* set up a connection */
	memset(&sock, '\0', sizeof sock);
#ifdef BSD
	sock.sun_len = sizeof sock;
#endif /* BSD */
	sock.sun_family = PF_UNIX;
	strlcpy(sock.sun_path, colon + 1, sizeof sock.sun_path);

	/* try to connect */
	if (connect(s, (struct sockaddr *) &sock, (socklen_t) sizeof sock) != 0)
	{
		/* if ECONNREFUSED, try to unlink */
		if (errno == ECONNREFUSED)
		{
			close(s);

			if (unlink(sock.sun_path) == 0)
				return 0;
			else
				return errno;
		}

		/* if ENOENT, the socket's not there */
		else if (errno == ENOENT)
		{
			close(s);

			return 0;
		}

		/* something else happened */
		else
		{
			int saveerr;

			saveerr = errno;

			close(s);

			return saveerr;
		}
	}

	/* connection apparently succeeded */
	close(s);
	return EADDRINUSE;
}

/*
**  DMARCF_LOWERCASE -- lowercase-ize a string
**
**  Parameters:
**  	str -- string to convert
**
**  Return value:
**  	None.
*/

void
dmarcf_lowercase(u_char *str)
{
	u_char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (isascii(*p) && isupper(*p))
			*p = tolower(*p);
	}
}

/*
**  DMARCF_INET_NTOA -- thread-safe inet_ntoa()
**
**  Parameters:
**  	a -- (struct in_addr) to be converted
**  	buf -- destination buffer
**  	buflen -- number of bytes at buf
**
**  Return value:
**  	Size of the resultant string.  If the result is greater than buflen,
**  	then buf does not contain the complete result.
*/

size_t
dmarcf_inet_ntoa(struct in_addr a, char *buf, size_t buflen)
{
	in_addr_t addr;

	assert(buf != NULL);

	addr = ntohl(a.s_addr);

	return snprintf(buf, buflen, "%d.%d.%d.%d",
	                (addr >> 24), (addr >> 16) & 0xff,
	                (addr >> 8) & 0xff, addr & 0xff);
}
