ACLOCAL_AMFLAGS = -I m4

bindir=@LIBDMARC_DIR@/bin
libdir=@LIBDMARC_DIR@/lib
includedir=@LIBDMARC_DIR@/include

SUBDIRS		= libopendmarc docs opendmarc reports

auxdir		= @ac_aux_dir@
AUX_DIST	= $(auxdir)/install-sh $(auxdir)/missing \
		  $(auxdir)/mkinstalldirs \
		  $(auxdir)/config.guess $(auxdir)/build \
		  $(auxdir)/dh.m4


AUTOMAKE_OPTIONS 	= foreign
MAINTAINERCLEANFILES 	= Makefile.in aclocal.m4 configure \
			  $(AUX_DIST)

ACLOCAL		= aclocal -I $(auxdir)
EXTRA_DIST	= libopendmarc/tests/testfiles/effective_tld_names.dat

dist-hook:	
	 if [ -f opendmarc-0.1.0/dmarc.h ]; then rm -f opendmarc-0.1.0/dmarc.h; fi
	 sed -e '/OPENDMARC_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < libopendmarc/dmarc.h > $(distdir)/dmarc.h


install-exec-local:


