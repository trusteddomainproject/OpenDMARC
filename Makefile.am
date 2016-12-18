ACLOCAL_AMFLAGS = -I m4

libdir=@LIBDMARC_DIR@/lib
includedir=@LIBDMARC_DIR@/include

SUBDIRS		= contrib db docs libopendmarc reports
if BUILD_FILTER
SUBDIRS         += opendmarc
endif

auxdir		= @ac_aux_dir@
AUX_DIST	= $(auxdir)/install-sh $(auxdir)/missing \
		  $(auxdir)/mkinstalldirs \
		  $(auxdir)/config.guess $(auxdir)/build \
		  $(auxdir)/dh.m4


AUTOMAKE_OPTIONS 	= foreign
MAINTAINERCLEANFILES 	= Makefile.in aclocal.m4 configure \
			  $(AUX_DIST)

ACLOCAL		= aclocal -I $(auxdir)

dist_doc_DATA = LICENSE LICENSE.Sendmail

DISTCLEANFILES = opendmarc-@VERSION@.tar.gz

DISTCHECK_CONFIGURE_FLAGS=--enable-filter-tests

dist-hook:	
	[ -f $(distdir)/libopendmarc/dmarc.h ] && rm -f $(distdir)/libopendmarc/dmarc.h
	sed -e '/OPENDMARC_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < $(srcdir)/libopendmarc/dmarc.h > $(distdir)/libopendmarc/dmarc.h
	echo "looking to see if @VERSION@ is in the RELEASE_NOTES"
	fgrep @VERSION@ $(srcdir)/RELEASE_NOTES
	sed -e 's|\(@VERSION@[ \t]*\)[0-9?]\{4\}\(/[0-9?]\{2\}\)\{2\}|\1'`date +%Y/%m/%d`'|' < $(srcdir)/RELEASE_NOTES > $(distdir)/RELEASE_NOTES

$(DIST_ARCHIVES): distcheck

$(DIST_ARCHIVES).md5: $(DIST_ARCHIVES)
	md5 $? > $@ || md5sum $? > $@

$(DIST_ARCHIVES).sha1: $(DIST_ARCHIVES)
	sha1 $? > $@ || sha1sum $? > $@

$(DIST_ARCHIVES).asc: $(DIST_ARCHIVES)
	gpg -a -u security@trusteddomain.org --detach-sign $?

push: $(DIST_ARCHIVES) $(DIST_ARCHIVES).sha1 $(DIST_ARCHIVES).md5 $(DIST_ARCHIVES).asc
	@echo "Are you sure you want to tag and release $(DIST_ARCHIVES)? (y/n)"
	@read confirm && [ $$confirm = 'y' ]
	git tag rel-opendmarc-`echo $(VERSION) | sed 's/\./-/g'`
	git push --tags
	scp $(DIST_ARCHIVES) $(DIST_ARCHIVES).sha1 $(DIST_ARCHIVES).md5 $(DIST_ARCHIVES).asc RELEASE_NOTES cm-msk,opendmarc@frs.sourceforge.net:/home/frs/project/o/op/opendmarc/

.PHONY: push
