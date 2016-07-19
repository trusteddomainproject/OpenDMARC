/***********************************************************************
** OPENDMARC_DNS.C
**	DMARC_DNS_GET_RECORD -- looks up and returns the txt record
**	DMARC_DNS_TEST_RECORD -- hook to test
** 
**  Copyright (c) 2012-2016, The Trusted Domain Project.  All rights reserved.
************************************************************************/ 

#ifndef BIND_8_COMPAT
# define BIND_8_COMPAT
#endif /* ! BIND_8_COMPAT */

#include <netdb.h>

#include "opendmarc_internal.h"

#ifndef MAXPACKET
# define MAXPACKET        (8192)
#endif

struct fake_dns_data
{
	const char *		fdns_name;
	const char *		fdns_answer;
	struct fake_dns_data *	fdns_next;
};

static struct fake_dns_data * fake_dns = NULL;
static struct fake_dns_data * fake_dns_tail = NULL;

/*************************************************************************
** OPENDMARC_DNS_FAKE_RECORD -- store a fake DNS reply
**
** Arguments:
**	name			-- name of fake record to add
**	answer			-- answer to fake record
**
** Return Values:
**	None.
**
** Side Effects:
**	Calls to dmarc_dns_get_record() will check this list for an answer
**  	rather than using live DNS.  This is intended to be used by test
**  	harnesses that have no DNS access.
*************************************************************************/
void
opendmarc_dns_fake_record(const char *name, const char *answer)
{
	struct fake_dns_data *new;

	if (name == NULL)
		return;

	new = malloc(sizeof *new);
	if (new != NULL)
	{
		new->fdns_name = strdup(name);
		if (new->fdns_name == NULL)
		{
			free(new);
			return;
		}

		new->fdns_answer = strdup(answer);
		if (new->fdns_answer == NULL)
		{
			free((void *) new->fdns_name);
			free(new);
			return;
		}

		new->fdns_next = NULL;

		if (fake_dns == NULL)
		{
			fake_dns = new;
			fake_dns_tail = new;
		}
		else
		{
			fake_dns_tail->fdns_next = new;
			fake_dns_tail = new;
		}
	}
}

/*************************************************************************
** DMARC_DNS_GET_RECORD -- looks up and returns the txt record
**
** Arguments:
**	domain			-- the domain name to look up.
**	reply			-- pointer to an integer to get query status
**	got_txtbuf		-- where to scribble the found txt record
**	got_txtlen		-- size of txt record buffer
**
** Return Values:
**	got_txtbuf		-- pointer to got_txtbuf on success
**	NULL			-- otherise, and place the h_errno error into reply
**
** Side Effects:
**	Makes a connection to the local (or specified)
**      name server and and may block waiting for a reply.
**
*************************************************************************/
char *
dmarc_dns_get_record(char *domain, int *reply, char *got_txtbuf, size_t got_txtlen)
{
	u_char *	end_ptr	= NULL;
	u_char *	cur_ptr	= NULL;
	u_char *	got_ptr	= NULL;
	u_char *	gote_ptr = NULL;
	int		ch	= 0;
	short		cur_len	= 0;
	HEADER		header;
	int		class	= -1;
	int		acnt	= -1;
	int		qdcnt	= -1;
	u_short		type	= 0;
	u_long		ttl	= 0;
	char *		bp	= NULL;
	int		fake_reply	= 0;
	int *		reply_ptr	= NULL;
	u_char		answer_buf[MAXPACKET];
	int 		answer_len;
	char		hbuf[MAXDNSHOSTNAME];
	char		namebuf[MAXDNSHOSTNAME + 1];
#if HAVE_RES_NINIT
	struct __res_state resp;
#endif /* HAVE_RES_NINIT */     

	/*
	 * Short circuit the return "reply" if no variable provided.
	 */
	if (reply == NULL)
		reply_ptr = &fake_reply;
	else
		reply_ptr = reply;

	/*
	 * If a null or empy domain was given to us, just say that it
	 * was not found.
	 */
	*reply_ptr = 0;
	if (domain == NULL || *domain == '\0')
	{
		*reply_ptr = HOST_NOT_FOUND;
		return NULL;
	}
	/*
	 * If no buffer was supplied to return the txt record,
	 * pretend nothing was found.
	 */
	if (got_txtbuf == NULL || got_txtlen == 0)
	{
		*reply_ptr = HOST_NOT_FOUND;
		return NULL;
	}

	/*
	 * Pull the answer from the fake DNS table if there is one.
	 */
	if (fake_dns != NULL)
	{
		struct fake_dns_data *cur;

		for (cur = fake_dns; cur != NULL; cur = cur->fdns_next)
		{
			if (strcasecmp(cur->fdns_name, domain) == 0)
			{
				strncpy(got_txtbuf, cur->fdns_answer,
				        got_txtlen - 1);
				*reply_ptr = NETDB_SUCCESS;
				return got_txtbuf;
			}
		}

		*reply_ptr = NO_DATA;
		return NULL;
	}

	/*
	 * Copy the domain so we can scribble on it. The orginal
	 * may point to a static string.
	 * We should use strlcpy(), but not all systems have it.
	 */
	(void) memset(hbuf, '\0', sizeof hbuf);
	(void) strncpy(hbuf, domain, sizeof hbuf - 1);
	bp = hbuf;

	/*
	 * Make sure host ends in a dot to short circuit lookups
	 */
	bp = hbuf + strlen(hbuf) - 1;
	if (*bp != '.')
		*++bp = '.';
	*++bp = '\0';
	/* 
	 * Make user host does not begin with a dot.
	 */
	bp = hbuf;
	while (*bp == '.')
		++bp;

#ifdef HAVE_RES_NINIT   
	memset(&resp, '\0', sizeof resp);
	resp.options |= RES_DEFAULT;
#if defined RES_USE_DNSSEC
	resp.options |= RES_USE_DNSSEC;
#endif
	res_ninit(&resp);
	(void) opendmarc_policy_library_dns_hook(&resp.nscount,
                                                 &resp.nsaddr_list);
	answer_len = res_nquery(&resp, bp, C_IN, T_TXT, answer_buf, sizeof answer_buf);
	res_nclose(&resp);
#else /* HAVE_RES_NINIT */
#if defined RES_USE_DNSSEC
	_res.options |= RES_USE_DNSSEC;
#endif
	(void) opendmarc_policy_library_dns_hook(&_res.nscount,
                                                 _res.nsaddr_list);
	answer_len = res_query(bp, C_IN, T_TXT, answer_buf, sizeof answer_buf);
#endif /* HAVE_RES_NINIT */
	if (answer_len < 0)
	{
		if (h_errno == NETDB_SUCCESS)
			h_errno = NO_DATA;
		*reply_ptr = h_errno;
		return NULL;
	}
	/*
	 * Truncate answer if it is too big.
	 */
	if (answer_len > sizeof answer_buf)
		answer_len = sizeof answer_buf;

	(void) memcpy(&header, answer_buf, sizeof header);
	cur_ptr = (u_char *)&answer_buf + HFIXEDSZ;
	end_ptr = (u_char *)&answer_buf + answer_len;

	(void) memset(namebuf, '\0', sizeof namebuf);
	/* skip question part of response -- we know what we asked */
	for (qdcnt = ntohs(header.qdcount); qdcnt > 0; qdcnt--)
	{
		(void) dn_expand((unsigned char *) &answer_buf, end_ptr,
		                 cur_ptr, namebuf, sizeof namebuf);
		if ((answer_len = dn_skipname(cur_ptr, end_ptr)) < 0)
		{
			*reply_ptr = NO_DATA;
			return NULL;
		}
		cur_ptr += answer_len;
		if (cur_ptr + INT16SZ + INT16SZ > end_ptr)
		{
			*reply_ptr = NO_DATA;
			return NULL;
		}
		GETSHORT(type, cur_ptr);  
		GETSHORT(class, cur_ptr);
	}
	if (header.rcode != NOERROR)
	{
		*reply_ptr = NO_DATA;
		return NULL;
	}
	acnt = ntohs((unsigned short) header.ancount);
	if (acnt == 0)
	{
		*reply_ptr = NO_DATA;
		return NULL;
	}
	while (--acnt >= 0 && cur_ptr < end_ptr)
	{
		if ((answer_len = dn_expand((unsigned char *) &answer_buf,
		                            end_ptr, cur_ptr, namebuf,
		                            sizeof namebuf)) < 0)
		{
			*reply_ptr = NO_DATA;
			return NULL;
		}
		cur_ptr += answer_len;

		if (cur_ptr + INT16SZ + INT16SZ > end_ptr)
		{
			/* currupt answer */
			*reply_ptr = NO_DATA;
			return NULL;
		}
		GETSHORT(type, cur_ptr);
		GETSHORT(class, cur_ptr);
		/* we may want to use the ttl later */
		GETLONG(ttl, cur_ptr);

		if (type == T_CNAME)
		{
			/*
			 * Copy the cname just incase the resolver
			 * didn't also follow it an give us the text
			 * record.
			 */

			if (got_txtbuf[0] == '\0')
			{
				(void) memset(got_txtbuf, '\0', got_txtlen);
				answer_len = dn_expand((unsigned char *)&answer_buf,
						end_ptr, cur_ptr,
						got_txtbuf, got_txtlen);
				cur_ptr += answer_len;
			}
			else
			{
				cur_ptr += dn_skipname(end_ptr, cur_ptr);
			}

			continue;
		}
#ifdef T_RRSIG
		else if (type == T_RRSIG)
		{
			GETSHORT(answer_len, cur_ptr);
			cur_ptr += answer_len;
		}
#endif /* T_RRSIG */
		else if (type != T_TXT)
		{
			/*
			 * TODO: Fail or should we ignore it?
			 */
			*reply_ptr = NO_DATA;
			return NULL;
		}

		if (cur_ptr + INT16SZ > end_ptr)
		{
			/* 
			 * Yikes. No payload length 
			 */
			*reply_ptr = NO_DATA;
			return NULL;
		}
		GETSHORT(cur_len, cur_ptr);

		if (cur_ptr + cur_len > end_ptr)
		{
			/* 
			 * If the payload length greater than remaining buffer 
			 */
			*reply_ptr = NO_DATA;
			return NULL;
		}
		(void) memset(got_txtbuf, '\0', got_txtlen);
		/* copy the returned record into got_txtbuf */
		got_ptr  = (u_char *)got_txtbuf;
		gote_ptr = (u_char *)got_txtbuf + got_txtlen -1;
		while (cur_len > 0 && got_ptr < gote_ptr)
		{
			ch = *cur_ptr++;
			cur_len--;
			while (ch > 0 && got_ptr < gote_ptr)
			{
				*got_ptr++ = *cur_ptr++;
				ch--;
				cur_len--;
			}
		}
		if (strstr(got_txtbuf, "v=DMARC") != NULL)
		{
			*reply_ptr = NETDB_SUCCESS;
			return got_txtbuf;
		}
		*got_txtbuf = '\0';
		cur_ptr += cur_len;
		cur_ptr += answer_len;
		continue;
	}
	*reply_ptr = NO_DATA;
	return NULL;
}
