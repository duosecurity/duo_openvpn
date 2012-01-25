ifdef USE_PERL
CFLAGS=-DUSE_PERL
SCRIPT_NAME=duo_openvpn.pl
else
SCRIPT_NAME=duo_openvpn.py
endif

all: duo_openvpn.so

duo_openvpn.o: duo_openvpn.c
	gcc $(CFLAGS) -fPIC -c duo_openvpn.c

duo_openvpn.so: duo_openvpn.o
	gcc -fPIC -shared -Wl,-soname,duo_openvpn.so -o duo_openvpn.so duo_openvpn.o -lc	

install: duo_openvpn.so
	mkdir -p /opt/duo
	cp duo_openvpn.so /opt/duo
	cp $(SCRIPT_NAME) /opt/duo
	chmod 755 /opt/duo/duo_openvpn.so
	chmod 755 /opt/duo/$(SCRIPT_NAME)

uninstall:
	rm -rf /opt/duo

clean:
	rm -f *.so *.o
