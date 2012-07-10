# This Makefile builds and optionally installs the duo openvpn plugin and
# helper scripts.  It also allows you to build an RPM, if you happen to be
# on a platform that supports that.
#
# You can specify whether or not to default to use Perl or Python for the
# command-line utility; the RPM will default to python but install both
# versions.
#
# Note: we first look for python version 2.6; if that isn't found, we try
# 'python'.  This is rather hackish and somebody with the required
# python-fu should fix this up.
NAME=duo_openvpn

ifndef PREFIX
PREFIX=/usr
endif

ifdef USE_PERL
SUFFIX=pl
else
SUFFIX=py
endif

PYTHON=$(shell which python26 2>/dev/null)

ifeq ($(strip $(PYTHON)),)
PYTHON=$(shell which python)
endif

all: prefix-updates ${NAME}.so

rpm: all
	sh mkrpm.sh ${NAME}

prefix-updates: ${NAME}.c ${NAME}.py ${NAME}.pl

${NAME}.py: ${NAME}.py.in
	sed -e "s|__PREFIX__|${PREFIX}|g" -e "s|__PYTHON__|${PYTHON}|g" $< > $@

${NAME}.pl: ${NAME}.pl.in
	sed -e "s|__PREFIX__|${PREFIX}|g" $< > $@

${NAME}.c: ${NAME}.c.in
	sed -e "s|__PREFIX__|${PREFIX}|g" $< > $@

${NAME}.o: ${NAME}.c
	gcc $(CFLAGS) -fPIC -c ${NAME}.c

${NAME}.so: ${NAME}.o
	gcc -fPIC -shared -Wl,-soname,${NAME}.so -o ${NAME}.so ${NAME}.o -lc

install: ${NAME}.so
	mkdir -p ${PREFIX}/bin
	mkdir -p ${PREFIX}/lib
	mkdir -p ${PREFIX}/share/duo
	install -c -m 644 ca_certs.pem ${PREFIX}/share/duo/ca_certs.pem
	install -c -m 755 ${NAME}.py ${PREFIX}/share/duo/${NAME}.pl
	install -c -m 755 ${NAME}.py ${PREFIX}/share/duo/${NAME}.py
	install -c -m 755 ${NAME}.so ${PREFIX}/lib/${NAME}.so
	install -c -m 644 https_wrapper.py ${PREFIX}/share/duo/https_wrapper.py
	ln -s ${PREFIX}/share/duo/${NAME}.${SUFFIX} ${PREFIX}/bin/${NAME}

uninstall:
	rm -rf ${PREFIX}/share/duo
	rm -f ${PREFIX}/lib/${NAME}.so
	rm -f ${PREFIX}/bin/${NAME}

clean:
	rm -f *.so *.o ${NAME}.c ${NAME}.py ${NAME}.pl
