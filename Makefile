ifdef USE_PERL
CFLAGS=-DUSE_PERL
SCRIPT_NAME=duo_openvpn.pl
else
SCRIPT_NAME=duo_openvpn.py
endif

include config.mk

all: CONFIG duo_openvpn.so

config.mk:
	@echo "No configuration found. Creating a default configuration."
	@echo "Rerun make to use defaults, or run ./configure --help to see options."
	./configure
	@false


duo_openvpn.o: duo_openvpn.c
	cc $(CFLAGS) -fPIC -c duo_openvpn.c

duo_openvpn.so: duo_openvpn.o
	cc -fPIC -shared -Wl,-soname,duo_openvpn.so -o duo_openvpn.so duo_openvpn.o -lc

install: duo_openvpn.so
	mkdir -p $(DESTDIR)
	cp duo_openvpn.so $(DESTDIR)
	chmod 755 $(DESTDIR)/duo_openvpn.so
	cp ca_certs.pem $(DESTDIR)
	chmod 644 $(DESTDIR)/ca_certs.pem
ifdef USE_PERL
	cp duo_openvpn.pl $(DESTDIR)
	chmod 755 $(DESTDIR)/duo_openvpn.pl
else
	cp duo_openvpn.py $(DESTDIR)
	cp https_wrapper.py $(DESTDIR)
	chmod 755 $(DESTDIR)/duo_openvpn.py
	chmod 644 $(DESTDIR)/https_wrapper.py
endif

uninstall:
	rm -f $(DESTDIR)/duo_openvpn.so
	rm -f $(DESTDIR)/ca_certs.pem
	rm -f $(DESTDIR)/duo_openvpn.pl
	rm -f $(DESTDIR)/duo_openvpn.py
	rm -f $(DESTDIR)/https_wrapper.py

clean:
	rm -f *.so *.o

CONFIG: config.mk
.PHONY: CONFIG
