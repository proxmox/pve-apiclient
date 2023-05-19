PACKAGE=libpve-apiclient-perl
PKGVER=$(shell dpkg-parsechangelog -Sversion | cut -d- -f1)
PKGREL=$(shell dpkg-parsechangelog -Sversion | cut -d- -f2)

BUILDSRC := $(PACKAGE)-$(PKGVER)
DEB=$(PACKAGE)_$(PKGVER)-$(PKGREL)_all.deb
DSC=$(PACKAGE)_$(PKGVER)-$(PKGREL).dsc

DESTDIR=

PERL5DIR=$(DESTDIR)/usr/share/perl5
DOCDIR=$(DESTDIR)/usr/share/doc/$(PACKAGE)

GITVERSION:=$(shell git rev-parse HEAD)

all: $(DEB)

.PHONY: $(BUILDSRC)
$(BUILDSRC):
	rm -rf $(BUILDSRC)
	rsync -a debian $(BUILDSRC)
	make DESTDIR=./$(BUILDSRC) install
	echo "git clone git://git.proxmox.com/git/pve-apiclient.git\\ngit checkout $(GITVERSION)" > $(BUILDSRC)/debian/SOURCE

.PHONY: deb
deb $(DEB): $(BUILDSRC)
	cd $(BUILDSRC); dpkg-buildpackage -rfakeroot -b -us -uc
	lintian $(DEB)

.PHONY: dsc
dsc: $(BUILDSRC)
	cd $(BUILDSRC); dpkg-buildpackage -S -us -uc -d -nc
	lintian $(DSC)

install:
	install -D -m 0644 PVE/APIClient/LWP.pm $(PERL5DIR)/PVE/APIClient/LWP.pm
	install -m 0644 PVE/APIClient/Exception.pm $(PERL5DIR)/PVE/APIClient/Exception.pm
	install -d -m 755 $(DOCDIR)/examples
	install -m 0755 examples/example1.pl $(DOCDIR)/examples
	install -m 0755 examples/example2.pl $(DOCDIR)/examples
	install -m 0755 examples/perftest1.pl $(DOCDIR)/examples

.PHONY: upload
upload: $(DEB)
	tar cf - $(DEB) | ssh -X repoman@repo.proxmox.com upload --product pmg,pve --dist bullseye

distclean: clean

clean:
	rm -rf ./$(BUILDSRC) *.deb *.changes *.buildinfo *.dsc *.tar.gz

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)
