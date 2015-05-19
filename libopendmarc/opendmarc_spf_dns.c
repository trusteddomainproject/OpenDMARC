#include "opendmarc_internal.h"

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

#include <netdb.h>

#include "dmarc.h"

#if WITH_SPF && ! HAVE_SPF2_H
/*
** Beware that some Linux versions incorrectly define 
** MAXHOSTNAMELEN as 64, but DNS lookups require a length
** of 255. So we don't use MAXHOSTNAMELEN here.
*/
#define MAXDNSHOSTNAME 256
#ifndef MAXPACKET
# define MAXPACKET        (8192)
#endif
#ifndef T_SPF
# define T_SPF	(99)
#endif

/***************************************************************************************************
** opendmarc_spf_dns_lookup_a_actual -- Looks type of address that is sought
**
** Arguments:
**	domain		-- the domain name to look up.
**	sought		-- type of lookup A or AAAA
**	ary		-- array of strings containing list of IP addresses
**	cnt		-- Pointer to count of lines in array
** Returns:
**	ary	-- on success
**	NULL	-- otherise, and place the h_errno error into reply
** Side Effects:
**	Makes a connection to the local name server and blocks
**	waiting for a reply.
***************************************************************************************************/

char **
opendmarc_spf_dns_lookup_a_actual(char *domain, int sought, char **ary, int *cnt)
{
	char *		bp;
	u_char *	cp;
	u_char *	eom	= NULL;
	char		hbuf[MAXDNSHOSTNAME];
	char		namebuf[MAXDNSHOSTNAME + 1];
	u_char		a_buf[MAXPACKET];
	struct in_addr	in;
	uint32_t	a;
	HEADER		hdr;
	int		k;
	short		l	= 0;
	int		class	= -1;
	int		acnt	= -1;
	int		qdcnt	= -1;
	u_short		type	= 0;
	u_long		ttl	= 0;
#if HAVE_RES_NINIT
	struct __res_state resp;
#endif /* HAVE_RES_NINIT */

	/*
	 * If a null or empy domain was given to us, just say it
	 * was not found.
	 */
	if (domain == NULL || *domain == '\0')
	{
		return NULL;
	}

#ifdef HAVE_RES_NINIT 
        memset(&resp, '\0', sizeof resp);
	res_ninit(&resp);
#endif /* HAVE_RES_NINIT */
	/*
	 * Copy the domain so we can scribble on it. The orginal
	 * may point to a static string.
	 */
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
	if (*bp == '.')
		++bp;

#ifdef HAVE_RES_NINIT
	k = res_nquery(&resp, bp, C_IN, sought, a_buf, sizeof a_buf);
	res_nclose(&resp);
#else /* HAVE_RES_NINIT */
	k = res_query(bp, C_IN, sought, a_buf, sizeof a_buf);
#endif /* HAVE_RES_NINIT */
	if (k < 0)
	{
		return NULL;
	}
	if (k > (int)(sizeof a_buf))
	{
		k = sizeof a_buf;
	}
	(void) memcpy(&hdr, a_buf, sizeof hdr);
	cp = (u_char *)&a_buf + HFIXEDSZ;
	eom = (u_char *)&a_buf + k;

	(void) memset(namebuf, '\0', sizeof namebuf);
	/* skip question part of response -- we know what we asked */
	for (qdcnt = ntohs(hdr.qdcount); qdcnt > 0; qdcnt--)
	{
		k = dn_expand((unsigned char *) &a_buf, eom, cp, namebuf, sizeof namebuf);
		cp += k;
		if (cp + INT16SZ + INT16SZ > eom)
		{
			return NULL;
		}
		GETSHORT(type, cp);  
		GETSHORT(class, cp);
	}
	if (hdr.rcode != NOERROR)
	{
		return NULL;
	}
	acnt = ntohs((unsigned short) hdr.ancount);
	if (acnt == 0)
	{
		return NULL;
	}
	while (--acnt >= 0 && cp < eom)
	{
		if ((k = dn_expand((unsigned char *) &a_buf, eom, cp,
				   namebuf, sizeof namebuf)) < 0)
		{
			break;
		}
		cp += k;

		GETSHORT(type, cp);
		GETSHORT(class, cp);
		GETLONG(ttl, cp);
		GETSHORT(l, cp);
		if (type == T_CNAME)
		{
			char cname[MAXDNSHOSTNAME + 1];

			k = dn_expand((u_char *) &a_buf, eom, cp,
				cname, MAXDNSHOSTNAME);
			cp += k;
			continue;
		}
		if (type != type)
		{
			cp += l;
			continue;
		}

		GETLONG(a, cp);
		(void) memcpy(&in.s_addr, &a, sizeof(uint32_t));
		in.s_addr = ntohl(in.s_addr);
		(void) memset(hbuf, '\0', sizeof hbuf);
		(void) strncpy(hbuf, inet_ntoa(in), sizeof hbuf);
		ary = opendmarc_util_pushnargv(hbuf, ary, cnt);
	}
	return ary;
}

/***************************************************************************************************
** opendmarc_spf_dns_lookup_a -- Looks up the IPv4 and IPv6 addresses of the domain
**
** Arguments:
**	domain		-- the domain name to look up.
**	ary		-- array of strings containing list of IP addresses
**	cnt		-- Pointer to count of lines in array
** Returns:
**	ary	-- on success
**	NULL	-- otherise, and place the h_errno error into reply
** Side Effects:
**	Makes a connection to the local name server and blocks
**	waiting for a reply.
***************************************************************************************************/
char **
opendmarc_spf_dns_lookup_a(char *domain, char **ary, int *cnt)
{
	char **retp;

	retp = opendmarc_spf_dns_lookup_a_actual(domain, T_A, ary, cnt); 
#ifdef T_AAAA
	retp = opendmarc_spf_dns_lookup_a_actual(domain, T_AAAA, ary, cnt);
#endif /* T_AAAA */
	return retp;
}

/***************************************************************************************************
** opendmarc_spf_dns_lookup_mx -- Looks up the MX records for a domain
**
** Arguments:
**	domain		-- The domain name to look up.
**	ary		-- Array of strings containing list MX hosts
##			   Note that spf only cares if they exist.
**	cnt		-- Pointer to count of lines in array
** Returns:
**	ary	-- on success
**	NULL	-- otherise, and place the h_errno error into reply
** Side Effects:
**	Makes a connection to the local name server and blocks
**	waiting for a reply.
***************************************************************************************************/
char **
opendmarc_spf_dns_lookup_mx(char *domain, char **ary, int *cnt)
{
	register u_char *eob, *cp;
	register int k;
	u_char buf[BUFSIZ];
	HEADER *hp;
	union {
		HEADER  h;
		u_char  u[PACKETSZ];
	} q;
	int acnt, qdcnt;
	u_short pref;
	u_short type;
	u_long ttl;
#if HAVE_RES_NINIT
	struct __res_state resp;
#endif /* HAVE_RES_NINIT */

	if (domain == NULL)
	{
		return NULL;
	}

#ifdef HAVE_RES_NINIT 
        memset(&resp, '\0', sizeof resp);
	res_ninit(&resp);
	k = res_nquery(&resp, domain, C_IN, T_MX, (u_char *) &q, sizeof(q));
	res_nclose(&resp);
#else /* HAVE_RES_NINIT */
	k = res_query(domain, C_IN, T_MX, (u_char *) &q, sizeof(q));
#endif /* HAVE_RES_NINIT */

	if (k < 0)
	{
		return NULL;
	}
	hp  = &(q.h);  
	cp  = q.u + HFIXEDSZ;
	eob = q.u + k;

	for (qdcnt = ntohs(hp->qdcount); qdcnt--; cp += k + QFIXEDSZ)
		if ((k = dn_skipname(cp, eob)) < 0)
		{
			return NULL;
		}

	acnt = ntohs(hp->ancount);
	while (--acnt >= 0 && cp < eob)
	{
		if ((k = dn_expand(q.u, eob, cp, (char *)buf, BUFSIZ-1)) < 0)
			break;
		cp += k;
		if (cp > eob)
			break;
		GETSHORT(type, cp);
		cp += INT16SZ;
		GETLONG(ttl, cp);
		GETSHORT(k, cp);
		if (type != T_MX)
		{
			cp += k;
			continue;
		}
		GETSHORT(pref, cp);
		if ((k = dn_expand(q.u, eob, cp, (char *)buf, BUFSIZ-1)) < 0)
			break;
		cp += k;
		ary = opendmarc_spf_dns_lookup_a((char *)buf, ary, cnt);
	}
	return ary;
}

/***************************************************************************************************
** opendmarc_spf_dns_lookup_ptr -- Looks up IP address to get domain 
**
** Arguments:
**	domain		-- The domain name to look up.
**	ary		-- Array of strings containing list MX hosts
##			   Note that spf only cares if they exist.
**	cnt		-- Pointer to count of lines in array
** Returns:
**	ary	-- on success
**	NULL	-- otherise, and place the h_errno error into reply
** Side Effects:
**	Makes a connection to the local name server and blocks
**	waiting for a reply.
***************************************************************************************************/
char **
opendmarc_spf_dns_lookup_ptr(char *ip, char **ary, int *cnt)
{
	register u_char *eob, *cp;
	register int k;
	u_char buf[BUFSIZ];
	char	ip_buf[512];
	HEADER *hp;
	union {
		HEADER  h;
		u_char  u[PACKETSZ];
	} q;
	int acnt, qdcnt;
	u_short type;
	u_long ttl;
	char *icp;
#if HAVE_RES_NINIT
	struct __res_state resp;
#endif /* HAVE_RES_NINIT */

	if (ip == NULL)
	{
		return NULL;
	}
	(void) memset(buf, '\0', sizeof buf);
	(void) memset(ip_buf, '\0', sizeof ip_buf);
	(void) strlcpy(ip_buf, ip, sizeof ip_buf);
	icp = strrchr(ip_buf, '.');
	if (icp == NULL)
		return NULL;
	strlcpy((char *)buf, icp+1, sizeof buf);
	*icp = '\0';
	icp = strrchr(ip_buf, '.');
	if (icp == NULL)
		return NULL;
	strlcat((char *)buf, ".", sizeof buf);
	strlcat((char *)buf, icp+1, sizeof buf);
	*icp = '\0';
	icp = strrchr(ip_buf, '.');
	if (icp == NULL)
		return NULL;
	strlcat((char *)buf, ".", sizeof buf);
	strlcat((char *)buf, icp+1, sizeof buf);
	*icp = '\0';
	icp = ip_buf;
	strlcat((char *)buf, ".", sizeof buf);
	strlcat((char *)buf, icp, sizeof buf);
	strlcat((char *)buf, ".in-addr.arpa.", sizeof buf);

#ifdef HAVE_RES_NINIT 
        memset(&resp, '\0', sizeof resp);
	res_ninit(&resp);
	k = res_nquery(&resp, (char *)buf, C_IN, T_PTR, (u_char *) &q, sizeof(q));
	res_nclose(&resp);
#else /* HAVE_RES_NINIT */
	k = res_query((char *)buf, C_IN, T_PTR, (u_char *) &q, sizeof(q));
#endif /* HAVE_RES_NINIT */

	if (k < 0)
	{
		return NULL;
	}
	hp  = &(q.h);  
	cp  = q.u + HFIXEDSZ;
	eob = q.u + k;

	for (qdcnt = ntohs(hp->qdcount); qdcnt--; cp += k + QFIXEDSZ)
	{
		if ((k = dn_skipname(cp, eob)) < 0)
		{
			return NULL;
		}
	}

	acnt = ntohs(hp->ancount);
	while (--acnt >= 0 && cp < eob)
	{
		char ptr[MAXDNSHOSTNAME + 1];

		if ((k = dn_expand(q.u, eob, cp, (char *)buf, BUFSIZ-1)) < 0)
			break;
		cp += k;
		if (cp > eob)
			break;
		GETSHORT(type, cp);
		cp += INT16SZ;
		GETLONG(ttl, cp);
		GETSHORT(k, cp);

		k = dn_expand(q.u, eob, cp, ptr, MAXDNSHOSTNAME);
		ary = opendmarc_util_pushnargv(ptr, ary, cnt);
		cp += k;
		continue;
	}
	return ary;
}

/***************************************************************
** opendmarc_spf_dns_does_domain_exist -- does an a, aaaa, or mx record exist?
**
** Arguments:
**	domain	-- the domain name to look up.
**	reply	-- pointer to an integer
**
** Returns:
**	TRUE	-- if any of those records existed.
**	FALSE	-- otherise, and place the h_errno error
**		   into reply
**
** Side Effects:
**	Makes a connection to the local name server and bloks
**	waiting for a reply.
***************************************************************/
int
opendmarc_spf_dns_does_domain_exist(char *domain, int *reply)
{
	HEADER  hdr;
	u_char	a_q[MAXPACKET];
	u_char	aaaa_q[MAXPACKET];
	u_char	mx_q[MAXPACKET];
	int	r;
	int *	rp;
#if HAVE_RES_NINIT
	struct __res_state resp;
#endif /* HAVE_RES_NINIT */

	if (reply == NULL)
		rp = &r;
	else
		rp = reply;

	if (domain == NULL || *domain == '\0')
	{
		*rp = HOST_NOT_FOUND;
		return FALSE;
	}

        /*      
         * Make sure the domain exists.
         */
#ifdef HAVE_RES_NINIT 
        memset(&resp, '\0', sizeof resp);
	res_ninit(&resp);
        (void) res_nquery(&resp, domain, C_IN, T_A, a_q, sizeof a_q);  
#ifdef T_AAAA
        (void) res_nquery(&resp, domain, C_IN, T_AAAA, aaaa_q, sizeof aaaa_q);  
#endif /* T_AAAA */
        (void) res_nquery(&resp, domain, C_IN, T_MX, mx_q, sizeof mx_q);  
	res_nclose(&resp);
#else /* HAVE_RES_NINIT */
        (void) res_query(domain, C_IN, T_A, a_q, sizeof a_q);  
#ifdef T_AAAA
        (void) res_query(domain, C_IN, T_AAAA, aaaa_q, sizeof aaaa_q);  
#endif /* T_AAAA */
        (void) res_query(domain, C_IN, T_MX, mx_q, sizeof mx_q);  
#endif /* HAVE_RES_NINIT */
        
        memcpy(&hdr, a_q, sizeof hdr);     
	*rp = hdr.rcode;
        if (hdr.rcode == NOERROR)
		return TRUE;

        memcpy(&hdr, aaaa_q, sizeof hdr);     
	*rp = hdr.rcode;
        if (hdr.rcode == NOERROR)
		return TRUE;

        memcpy(&hdr, aaaa_q, sizeof hdr);     
	*rp = hdr.rcode;
        if (hdr.rcode == NOERROR)
		return TRUE;

	return FALSE;
}

/***************************************************************************************************
** opendmarc_dns_get_record -- looks up and returns the txt record
**
** Arguments:
**	domain		-- the domain name to look up.
**	reply		-- pointer to an integer
**	txt		-- where to scribble the found txt record
**	txtlen		-- size of txt record buffer
**	cname		-- buffer to hold CNAME if one found
**	cnamelen	-- size of cname buffer
**	spfcheck	-- restrict text records returned to just those beginning with v= or spf2.0
**
** Returns:
**	txt	-- on success
**	NULL	-- otherise, and place the h_errno error
**		   into reply
**	NULL	-- if no data, but cname may still contain a hostname
**
** Side Effects:
**	Makes a connection to the local name server and blocks
**	waiting for a reply.
***************************************************************************************************/
char *
opendmarc_spf_dns_get_record(char *domain, int *reply, char *txt, size_t txtlen, char *cname, size_t cnamelen, int spfcheck)
{
	u_char *	eom	= NULL;
	u_char *	eop	= NULL;
	u_char *	cp	= NULL;
	int 		k;
	u_char *	p	= NULL;
	int		ch	= 0;
	short		l	= 0;
	HEADER		hdr;
	int		class	= -1;
	int		acnt	= -1;
	int		qdcnt	= -1;
	u_short		type	= 0;
	u_long		ttl	= 0;
	char *		bp	= NULL;
	int		r	= 0;
	int *		rp	= NULL;
	u_char		txt_buf[MAXPACKET];
	char		hbuf[MAXDNSHOSTNAME];
	char		namebuf[MAXDNSHOSTNAME + 1];
#if HAVE_RES_NINIT
	struct __res_state resp;
#endif /* HAVE_RES_NINIT */

	if (reply == NULL)
		rp = &r;
	else
		rp = reply;

	/*
	 * If a null or empy domain was given to us, just say it
	 * was not found.
	 */
	*rp = 0;
	if (domain == NULL || *domain == '\0')
	{
		*rp = HOST_NOT_FOUND;
		return NULL;
	}

	if (cname != NULL && cnamelen > 0)
		(void) memset(cname, '\0', cnamelen);

	/*
	 * Copy the domain so we can scribble on it. The orginal
	 * may point to a static string.
	 */
	(void) memcpy(hbuf, domain, sizeof hbuf);
	bp = hbuf;
	if (txt != NULL)
		(void) memset(txt, '\0', txtlen);

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
	if (*bp == '.')
		++bp;

#ifdef HAVE_RES_NINIT 
        memset(&resp, '\0', sizeof resp);
	res_ninit(&resp);
	k = res_nquery(&resp, bp, C_IN, T_TXT, txt_buf, sizeof txt_buf);
#else /* HAVE_RES_NINIT */
	k = res_query(bp, C_IN, T_TXT, txt_buf, sizeof txt_buf);
#endif /* HAVE_RES_NINIT */
	if (k < 0)
	{
		/*
		 * TXT records apppear more common than SPF records, so
		 * we fall back to SPF instead of looking up SPF first.
		 */
		if (h_errno == NO_DATA || h_errno == NXDOMAIN)
		{
#ifdef HAVE_RES_NINIT 
			k = res_nquery(&resp, bp, C_IN, T_SPF, txt_buf, sizeof txt_buf);
#else /* HAVE_RES_NINIT */
			k = res_query(bp, C_IN, T_SPF, txt_buf, sizeof txt_buf);
#endif /* HAVE_RES_NINIT */
			if (k >= 0)
				goto got_spf_record;
		}
		*rp = h_errno;
#ifdef HAVE_RES_NINIT 
		res_nclose(&resp);
#endif /* HAVE_RES_NINIT */
		return NULL;
	}
got_spf_record:
#ifdef HAVE_RES_NINIT 
	res_nclose(&resp);
#endif /* HAVE_RES_NINIT */

	if (k > (int)(sizeof txt_buf))
		k = sizeof txt_buf;
	(void) memcpy(&hdr, txt_buf, sizeof hdr);
	cp = (u_char *)&txt_buf + HFIXEDSZ;
	eom = (u_char *)&txt_buf + k;

	(void) memset(namebuf, '\0', sizeof namebuf);
	/* skip question part of response -- we know what we asked */
	for (qdcnt = ntohs(hdr.qdcount); qdcnt > 0; qdcnt--)
	{
		(void) dn_expand((unsigned char *) &txt_buf, eom, cp, namebuf, sizeof namebuf);
		if ((k = dn_skipname(cp, eom)) < 0)
		{
			*rp = NO_DATA;
			return NULL;
		}
		cp += k;
		if (cp + INT16SZ + INT16SZ > eom)
		{
			*rp = NO_DATA;
			return NULL;
		}
		GETSHORT(type, cp);  
		GETSHORT(class, cp);
	}
	if (hdr.rcode != NOERROR)
	{
		*rp = NO_DATA;
		return NULL;
	}
	acnt = ntohs((unsigned short) hdr.ancount);
	if (acnt == 0)
	{
		*rp = NO_DATA;
		return NULL;
	}
	while (--acnt >= 0 && cp < eom)
	{
		if ((k = dn_expand((unsigned char *) &txt_buf, eom, cp,
				   namebuf, sizeof namebuf)) < 0)
		{
			*rp = NO_DATA;
			return NULL;
		}
		cp += k;

		if (cp + INT16SZ + INT16SZ > eom)
		{
			/* currupt answer */
			*rp = NO_DATA;
			return NULL;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
		if (type == T_CNAME)
		{
			/*
			 * CNAMEs are supposed to be invisible, but somtimes
			 * a CNAME points to a TXT record that times out, so
			 * all we get on the initial query is the CNAME.
			 */
			char	xname[MAXDNSHOSTNAME + 1];
			char *	xp;
			size_t	xlen;

			if (cname == NULL || cnamelen == 0)
			{
				xp = xname;
				xlen = sizeof xname;
			}
			else
			{
				xp = cname;
				xlen = cnamelen;
			}
			k = dn_expand((u_char *) &txt_buf, eom, (u_char *)cname, xp, xlen);
			cp += k;
			continue;
		}
		else if (type != T_TXT)
		{

			*rp = NO_DATA;
			return NULL;
		}
		/* we may want to cache the ttl later */
		GETLONG(ttl, cp);

		if (cp + INT16SZ > eom)
		{
			/* no payload length */
			*rp = NO_DATA;
			return NULL;
		}
		GETSHORT(l, cp);

		if (cp + l > eom)
		{
			/* payload length greater than remaining buffer */
			*rp = NO_DATA;
			return NULL;
		}
		if (txt != NULL)
		{
			(void) memset(txt, '\0', txtlen);
			/* 
			 * copy the returned record into txt 
			 */
			p = (u_char *)txt;
			eop = (u_char *)txt + txtlen -1;
			while (l > 0 && p < eop)
			{
				ch = *cp++;
				l--;
				while (ch > 0 && p < eop)
				{
					*p++ = *cp++;
					ch--;
					l--;
				}
			}
		}
		if (spfcheck == TRUE)
		{
			/*
			 * Honor both SPF and Sender Identity type records 
			 * But ignore mfrom/pra, because DMARC uses only SPF records.
			 */
			if (strstr(txt, "v=spf") != NULL || strncasecmp(txt, "spf2.0", 6) == 0)
			{
				*rp = 0;
				return txt;
			}
		}
		cp += l;
		continue;
	}
	*rp = NO_DATA;
	return NULL;
}

#endif /* WITH_SPF && ! HAVE_SPF2_H */
