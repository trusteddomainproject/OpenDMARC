bin_PROGRAMS		= test_dns_lookup test_tld
test_dns_lookup_LDFLAGS	= -L../ -lopendmarc
test_dns_lookup_SOURCES = test_dns_lookup.c
test_tld_LDFLAGS	= -L../ -lopendmarc
test_tld_SOURCES        = test_tld.c

test:
	@for name in $(bin_PROGRAMS); do ./$$name; done
