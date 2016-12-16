PACKAGE=libpve-apiclient-perl
PKGVER=1.0
PKGREL=1

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=/usr/share/perl5

all: ${DEB}

.PHONY: deb
deb ${DEB}:
	rm -rf build
	rsync -a debian build
	make DESTDIR=./build install
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}

install:
	install -D -m 0644 PVE/APIClient/LWP.pm ${DESTDIR}${PERL5DIR}/PVE/APIClient/LWP.pm

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

distclean: clean

clean:
	rm -rf ./build *.deb *.changes
	find . -name '*~' -exec rm {} ';'
