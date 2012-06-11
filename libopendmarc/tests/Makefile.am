bin_PROGRAMS		 = test_dns_lookup test_tld test_finddomain test_dmarc_parse
test_dns_lookup_LDFLAGS	 = -L../ -lopendmarc
test_dns_lookup_SOURCES  = test_dns_lookup.c
test_tld_LDFLAGS	 = -L../ -lopendmarc
test_tld_SOURCES         = test_tld.c
test_finddomain_LDFLAGS	 = -L../ -lopendmarc
test_finddomain_SOURCES  = test_finddomain.c
test_dmarc_parse_LDFLAGS = -L../ -lopendmarc
test_dmarc_parse_SOURCES = test_dmarc_parse.c

test:
	@for name in $(bin_PROGRAMS); do ./$$name; done
