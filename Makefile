PREFIX=/opt/duo
CFLAGS += -DPREFIX='"$(PREFIX)"'

ifdef USE_PERL
CFLAGS += -DUSE_PERL
SCRIPT_NAME=duo_openvpn.pl
else
SCRIPT_NAME=duo_openvpn.py
endif

all: duo_openvpn.so

duo_openvpn.o: duo_openvpn.c
	$(CC) $(CFLAGS) -fPIC -c duo_openvpn.c

duo_openvpn.so: duo_openvpn.o
	$(CC) -fPIC -shared -Wl,-soname,duo_openvpn.so -o duo_openvpn.so duo_openvpn.o -lc

install: duo_openvpn.so
	mkdir -p $(DESTDIR)$(PREFIX)
	install -c duo_openvpn.so -m 755 $(DESTDIR)$(PREFIX)
	install -c ca_certs.pem -m 644 $(DESTDIR)$(PREFIX)
ifdef USE_PERL
	install -c duo_openvpn.pl -m 755 $(DESTDIR)$(PREFIX)
else
	install -c duo_openvpn.py https_wrapper.py six.py -m 755 $(DESTDIR)$(PREFIX)
endif

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/duo_openvpn.so
	rm -f $(DESTDIR)$(PREFIX)/ca_certs.pem
	rm -f $(DESTDIR)$(PREFIX)/duo_openvpn.pl
	rm -f $(DESTDIR)$(PREFIX)/duo_openvpn.py
	rm -f $(DESTDIR)$(PREFIX)/https_wrapper.py
	rm -f $(DESTDIR)$(PREFIX)/six.py

clean:
	rm -f *.so *.o
