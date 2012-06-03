ACLOCAL_AMFLAGS = -I m4

bindir=@LIBDMARC_DIR@/bin
libdir=@LIBDMARC_DIR@/lib
includedir=@LIBDMARC_DIR@/include

SUBDIRS		= libopendmarc docs

auxdir		= @ac_aux_dir@
AUX_DIST	= $(auxdir)/install-sh $(auxdir)/missing \
		  $(auxdir)/mkinstalldirs \
		  $(auxdir)/config.guess $(auxdir)/build \
		  $(auxdir)/dh.m4


AUTOMAKE_OPTIONS 	= foreign
MAINTAINERCLEANFILES 	= Makefile.in aclocal.m4 configure \
			  $(AUX_DIST)

ACLOCAL		= aclocal -I $(auxdir)

dist-hook:	
	 [ -f $(distdir)/libopendmarc.h ] && rm -f $(distdir)/libopendmarc.h
	 sed -e '/OPENDMARC_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < $(srcdir)/libopendmarc.h > $(distdir)/libopendmarc.h


install-exec-local:


