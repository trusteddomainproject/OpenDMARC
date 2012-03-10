/********************************************************************
** OPENDMARC_DNS.C
**	DMARC_DNS_GET_RECORD -- looks up and returns the txt record
**	DMARC_DNS_TEST_RECORD -- hook to test
**********************************************************************/ 
#include "opendmarc_internal.h"

/*
** Beware that some Linux versions incorrectly define 
** MAXHOSTNAMELEN as 64, but DNS lookups require a length
** of 255. So we don't use MAXHOSTNAMELEN here. Instead
** we use MAXDNSHOSTNAME.
*/
#define MAXDNSHOSTNAME 256
#ifndef MAXPACKET
# define MAXPACKET        (8192)
#endif

/***************************************************************************************************
** DMARC_DNS_GET_RECORD -- looks up and returns the txt record
**
** Arguments:
**	domain			-- the domain name to look up.
**	reply			-- pointer to an integer to get query status
**	got_txtbuf		-- where to scribble the found txt record
**	got_txtlen		-- size of txt record buffer
**
** Return Values:
**	got_txtbuf		-- on success
**	NULL			-- otherise, and place the h_errno error into reply
**
** Side Effects:
**	Makes a connection to the local name server and and may block
**	waiting for a reply.
**
** Notes:
**	This routine expects your code to have already called res_init() and
**	to have conditioned res_retries and res_retrans as appropriate.
***************************************************************************************************/
char *
dmarc_dns_get_record(char *domain, int *reply, char *got_txtbuf, size_t got_txtlen)
{
	u_char *	end_ptr	= NULL;
	u_char *	cur_ptr	= NULL;
	u_char *	got_ptr	= NULL;
	u_char *	gote_ptr = NULL;
	int		ch	= 0;
	short		cur_len	= 0;
	short		got_len	= 0;
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
	extern int	h_errno;

	/*
	 * Short  circuit the return "reply" if no variable provided.
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
	 * Copy the domain so we can scribble on it. The orginal
	 * may point to a static string.
	 * We should use strlcopy(), but not all systems have it.
	 */
	(void) memset(hbuf, '\0', sizeof hbuf);
	(void) memcpy(hbuf, domain, sizeof hbuf);
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

	answer_len = res_query(bp, C_IN, T_TXT, answer_buf, sizeof answer_buf);
	if (answer_len < 0)
	{
		*reply_ptr = h_errno;
		return NULL;
	}
	/*
	 * Truncate answer it too big.
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
		(void) dn_expand((unsigned char *) &answer_buf, end_ptr, cur_ptr, namebuf, sizeof namebuf);
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
		if ((answer_len = dn_expand((unsigned char *) &answer_buf, end_ptr, cur_ptr, namebuf, sizeof namebuf)) < 0)
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
		if (type != T_TXT)
		{
			/*
			 * TODO: Fail or should we ignore it?
			 */
			*reply_ptr = NO_DATA;
			return NULL;
			//cur_ptr += answer_len;
			//continue;
		}
		/* we may want to use the ttl later */
		GETLONG(ttl, cur_ptr);

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
		while (got_len > 0 && got_ptr < gote_ptr)
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
			*reply_ptr = 0;
			return got_txtbuf;
		}
		cp += cur_len;
		continue;
	}
	*reply_ptr = NO_DATA;
	return NULL;
}

int
dmarc_dns_test_record(void)
{
	char * domain_list[] = {
		"_dmarc.bcx.com",	/* has a record */
		"_dmarc.mail.bcx.com",	/* exists but no record */
		"_dmarc.none.bcx.com",	/* does not exist */
		NULL,
	};
	int	i;
	char 	txt_record[2048];
	int	reply;
	char *	cp;
	int	success, failures;

	success = failures = 0;
	for (i = 0; i < 3; ++i)
	{
		cp = dmarc_dns_get_record(domain_list[i], &reply, txt_record, sizeof txt_record);
		switch (i)
		{
		    case 0:
			if (cp != NULL)
				++success;
			else
				++failures;
			break;
		    case (1):
			if (cp == NULL || reply != 0)
				++success;
			else
				++failures;
			break;
		    case (2)
			if (cp == NULL)
				++success;
			else
				++failures;
			break;
		}
	}
	printf("DNS Lookup _dmarc Records (3 Tests): %d pass, %d fail\n", success, failures);
	return failures;
}

