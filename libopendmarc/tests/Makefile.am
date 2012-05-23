bin_PROGRAMS		= test_dns_lookup
test_dns_lookup_LDFLAGS	= -L../ -lopendmarc
test_dns_lookup_SOURCES= test_dns_lookup.c

test:
	@for name in $(bin_PROGRAMS); do ./$$name; done
