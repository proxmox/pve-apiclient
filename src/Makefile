PACKAGE ?= libpve-apiclient-perl

DESTDIR=
PERL5DIR=$(DESTDIR)/usr/share/perl5
DOCDIR=$(DESTDIR)/usr/share/doc/$(PACKAGE)

all:

install: PVE/APIClient/Exception.pm PVE/APIClient/LWP.pm examples/*.pl
	install -D -m 0644 PVE/APIClient/LWP.pm $(PERL5DIR)/PVE/APIClient/LWP.pm
	install -m 0644 PVE/APIClient/Exception.pm $(PERL5DIR)/PVE/APIClient/Exception.pm
	install -d -m 755 $(DOCDIR)/examples
	install -m 0755 examples/example1.pl $(DOCDIR)/examples
	install -m 0755 examples/example2.pl $(DOCDIR)/examples
	install -m 0755 examples/perftest1.pl $(DOCDIR)/examples

clean:
