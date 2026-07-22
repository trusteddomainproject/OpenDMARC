/********************************************************************
** OPENDMARC_SPF_DNS_LOG.C -- a libspf2 DNS layer that logs SPF-record
**                             lookups for the RFC 6591/9991 SPF-DNS
**                             ARF field, without altering evaluation
**                             behavior
**********************************************************************/
# include "opendmarc_internal.h"

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

# include "dmarc.h"

#if WITH_SPF

#if HAVE_SPF2_H

#include <ctype.h>

/*
**  Per-layer private state.  "logbuf" is the address of a caller-owned
**  "char *" accumulator (see opendmarc_spf.c); this layer appends to
**  *logbuf but does not own it and never frees it, since it must
**  outlive this DNS layer's own teardown (SPF_server_free() runs
**  before opendmarc_spf2_test() hands the log back to its caller).
*/
struct opendmarc_spf_dns_log_ctx
{
	char **			logbuf;
};

/*
**  OPENDMARC_SPF_DNS_LOG_APPEND -- append one RFC 6591 "SPF-DNS:" line
**
**  Parameters:
**  	logbuf -- address of the caller-owned accumulator
**  	rrtype -- "txt" or "spf" (the ABNF's literal tokens)
**  	domain -- domain that was queried
**  	content -- raw DNS record content to quote
**
**  Return value:
**  	None.  Silently does nothing on allocation failure -- a missing
**  	SPF-DNS line is not worth failing report generation over.
**
**  Notes:
**  	"content" comes from a DNS response and so is attacker-influenced
**  	(any domain consulted during evaluation, including third parties
**  	reached via include:/redirect=, or the message's own claimed
**  	envelope domain).  '"' and '\' are backslash-escaped per RFC 5322
**  	quoted-string rules; CR and LF are dropped outright rather than
**  	escaped, since this text is later written raw into an outgoing
**  	message piped to sendmail (ReportCommand) -- allowing embedded
**  	CRLFs through would let a malicious DNS record inject additional
**  	header lines into the report.
*/

static void
opendmarc_spf_dns_log_append(char **logbuf, const char *rrtype,
                             const char *domain, const char *content)
{
	size_t oldlen;
	size_t addlen;
	size_t contentlen;
	size_t remain;
	char *newbuf;
	char *p;
	const char *c;
	int n;

	if (logbuf == NULL || rrtype == NULL || domain == NULL ||
	    content == NULL)
		return;

	oldlen = (*logbuf != NULL) ? strlen(*logbuf) : 0;
	contentlen = strlen(content);

	/* worst case: every content byte becomes a 2-byte escape */
	addlen = strlen("SPF-DNS: ") + strlen(rrtype) + strlen(" : ") +
	         strlen(domain) + strlen(" : \"") + (contentlen * 2) +
	         strlen("\"\n");

	newbuf = (char *) realloc(*logbuf, oldlen + addlen + 1);
	if (newbuf == NULL)
		return;
	*logbuf = newbuf;

	p = newbuf + oldlen;
	remain = addlen + 1;

	n = snprintf(p, remain, "SPF-DNS: %s : %s : \"", rrtype, domain);
	if (n < 0 || (size_t) n >= remain)
		return;
	p += n;
	remain -= (size_t) n;

	for (c = content; *c != '\0'; c++)
	{
		if (*c == '\r' || *c == '\n')
			continue;

		if (*c == '"' || *c == '\\')
		{
			if (remain < 2)
				break;
			*p++ = '\\';
			remain--;
		}

		if (remain < 1)
			break;
		*p++ = *c;
		remain--;
	}

	(void) snprintf(p, remain, "\"\n");
}

/*
**  OPENDMARC_SPF_DNS_LOG_LOOKUP -- SPF_dns_lookup_t implementation
**
**  Delegates to the layer below unconditionally (evaluation behavior
**  is never altered by this layer), then, for TXT/SPF-type queries,
**  logs any returned record whose content is itself an SPF policy
**  record -- i.e. begins "v=spf1 " (case-insensitively), or is any
**  record at all for the historic RR type 99 ("SPF"), which has no
**  other purpose.  This deliberately excludes unrelated TXT records
**  that might share a name with a real SPF record, matching RFC 6591's
**  "SPF record...used to obtain the SPF result" wording rather than
**  logging every TXT record ever seen at a queried name.
*/

static SPF_dns_rr_t *
opendmarc_spf_dns_log_lookup(SPF_dns_server_t *spf_dns_server,
                             const char *domain, ns_type rr_type,
                             int should_cache)
{
	struct opendmarc_spf_dns_log_ctx *lctx;
	SPF_dns_server_t *below;
	SPF_dns_rr_t *rr;
	int c;

	lctx = (struct opendmarc_spf_dns_log_ctx *) spf_dns_server->hook;
	below = spf_dns_server->layer_below;

	rr = below->lookup(below, domain, rr_type, should_cache);

	if (rr != NULL && rr->rr != NULL &&
	    (rr_type == ns_t_txt || rr_type == ns_t_spf))
	{
		for (c = 0; c < rr->num_rr; c++)
		{
			const char *txt = rr->rr[c]->txt;

			if (txt == NULL)
				continue;

			if (rr_type == ns_t_spf ||
			    strncasecmp(txt, "v=spf1 ", 7) == 0 ||
			    strcasecmp(txt, "v=spf1") == 0)
			{
				opendmarc_spf_dns_log_append(lctx->logbuf,
					rr_type == ns_t_spf ? "spf" : "txt",
					domain, txt);
			}
		}
	}

	return rr;
}

/*
**  OPENDMARC_SPF_DNS_LOG_DESTROY -- SPF_dns_destroy_t implementation
**
**  Frees this layer's own private state only.  The accumulator the
**  layer's hook points at is caller-owned and is not touched here.
*/

static void
opendmarc_spf_dns_log_destroy(SPF_dns_server_t *spf_dns_server)
{
	if (spf_dns_server == NULL)
		return;

	free(spf_dns_server->hook);
	free(spf_dns_server);
}

/*
**  OPENDMARC_SPF_DNS_LOG_NEW -- construct the logging DNS layer
**
**  Parameters:
**  	layer_below -- the DNS layer to delegate all lookups to
**  	logbuf -- address of a caller-owned "char *" accumulator
**  	          (initially NULL is fine; grown via realloc() as lines
**  	          are appended); must outlive this layer's own teardown
**  	debug -- passed through to the SPF_dns_server_t "debug" field
**
**  Return value:
**  	A new SPF_dns_server_t, or NULL on allocation failure.
*/

SPF_dns_server_t *
opendmarc_spf_dns_log_new(SPF_dns_server_t *layer_below, char **logbuf,
                          int debug)
{
	SPF_dns_server_t *spf_dns_server;
	struct opendmarc_spf_dns_log_ctx *lctx;

	spf_dns_server = (SPF_dns_server_t *) malloc(sizeof(SPF_dns_server_t));
	if (spf_dns_server == NULL)
		return NULL;
	(void) memset(spf_dns_server, '\0', sizeof(SPF_dns_server_t));

	lctx = (struct opendmarc_spf_dns_log_ctx *)
	       malloc(sizeof(struct opendmarc_spf_dns_log_ctx));
	if (lctx == NULL)
	{
		free(spf_dns_server);
		return NULL;
	}
	lctx->logbuf = logbuf;

	spf_dns_server->destroy = opendmarc_spf_dns_log_destroy;
	spf_dns_server->lookup = opendmarc_spf_dns_log_lookup;
	spf_dns_server->get_spf = NULL;
	spf_dns_server->get_exp = NULL;
	spf_dns_server->add_cache = NULL;
	spf_dns_server->layer_below = layer_below;
	spf_dns_server->name = "opendmarc-log";
	spf_dns_server->debug = debug;
	spf_dns_server->hook = lctx;

	return spf_dns_server;
}

#endif /* HAVE_SPF2_H */

#endif /* WITH_SPF */
