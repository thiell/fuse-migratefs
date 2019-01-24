SUBDIRS = lib

bin_PROGRAMS = migratefs

ACLOCAL_AMFLAGS = -Im4

EXTRA_DIST = m4/gnulib-cache.m4 rpm/fuse-migratefs.spec.template autogen.sh systemd/migratefs.service systemd/migratefs

migratefs_CFLAGS = -I . -I lib $(FUSE_CFLAGS)
migratefs_LDFLAGS =
migratefs_LDADD = lib/libgnu.a $(FUSE_LIBS)
migratefs_SOURCES = main.c

WD := $(shell pwd)

#man1_MANS = fuse-migratefs.1
#
#fuse-migratefs.1:
#	go-md2man -in $(abs_srcdir)/fuse-migratefs.1.md -out fuse-migratefs.1
#
#generate-man: fuse-migratefs.1
#	go-md2man -in migratefs.1.md -out migratefs.1

fuse-migratefs.spec: $(srcdir)/rpm/fuse-migratefs.spec.template
	sed -e 's|#VERSION#|$(VERSION)|g' < $< > $@

rpm: dist-gzip fuse-migratefs.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -ba --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" fuse-migratefs.spec

srpm: dist-gzip fuse-migratefs.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -bs --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" fuse-migratefs.spec
