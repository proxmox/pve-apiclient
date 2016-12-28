PACKAGE=libpve-apiclient-perl
PKGVER=1.0
PKGREL=2

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}

all: ${DEB}

.PHONY: deb
deb ${DEB}:
	rm -rf build
	rsync -a debian build
	make DESTDIR=./build install
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}

install:
	install -D -m 0644 PVE/APIClient/LWP.pm ${PERL5DIR}/PVE/APIClient/LWP.pm
	install -d -m 755 ${DOCDIR}/examples
	install -m 0755 examples/example1.pl ${DOCDIR}/examples
	install -m 0755 examples/example2.pl ${DOCDIR}/examples
	install -m 0755 examples/perftest1.pl ${DOCDIR}/examples

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

distclean: clean

clean:
	rm -rf ./build *.deb *.changes
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
