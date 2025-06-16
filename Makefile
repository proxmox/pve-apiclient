include /usr/share/dpkg/default.mk

PACKAGE=libpve-apiclient-perl

BUILDSRC := $(PACKAGE)-$(DEB_VERSION)
DEB=$(PACKAGE)_$(DEB_VERSION)_all.deb
DSC=$(PACKAGE)_$(DEB_VERSION).dsc

DESTDIR=
PERL5DIR=$(DESTDIR)/usr/share/perl5
DOCDIR=$(DESTDIR)/usr/share/doc/$(PACKAGE)

GITVERSION:=$(shell git rev-parse HEAD)

all: $(DEB)

.PHONY: tidy
tidy:
	git ls-files ':*.p[ml]'| xargs -n4 -P0 proxmox-perltidy

$(BUILDSRC):
	rm -rf $@ $@.tmp
	cp -a src $@.tmp
	cp -a debian $@.tmp/
	echo "git clone git://git.proxmox.com/git/pve-apiclient.git\\ngit checkout $(GITVERSION)" >$@.tmp/debian/SOURCE
	mv $@.tmp $@

.PHONY: deb
deb $(DEB): $(BUILDSRC)
	cd $(BUILDSRC); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: dsc
dsc: $(DSC)
$(DSC): $(BUILDSRC)
	cd $(BUILDSRC); dpkg-buildpackage -S -us -uc -d
	lintian $(DSC)

sbuild: $(DSC)
	sbuild $(DSC)

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEB)
	tar cf - $(DEB) | ssh -X repoman@repo.proxmox.com upload --product pmg,pve --dist $(UPLOAD_DIST)

distclean: clean
clean:
	rm -rf $(PACKAGE)-[0-9]*/ *.deb *.changes *.buildinfo *.build *.dsc *.tar.*

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)
