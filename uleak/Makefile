#
# Copyright (c) 2000-2008 Андрей Валяев (dron@infosec.ru)
# This code is licenced under the GPL3 (http://www.gnu.org/licenses/#GPL)
#

# Система номерации версий у меня своя.
VERSION_RELEASE = 0
VERSION_BETA = 0
VERSION_ALPHA = 1
VERSION_PATCH = 0

VERSION=${VERSION_RELEASE}.${VERSION_BETA}.${VERSION_ALPHA}

WFLAGS=-Wall -Wextra -Weffc++
OFLAGS=-O0 -ggdb3
CFLAGS=
LDFLAGS=-lc -lstdc++

ifneq ("${wildcard /usr/lib/libunwind*}x", "x")
	CFLAGS+=-DLIBUNWIND
	LDFLAGS+=-lunwind -lunwind-generic
endif

all: libuleak.a libuleak.so.${VERSION}

libuleak.a: uleak.o
	ar r $@ $<
	ranlib $@

libuleak.so.${VERSION} : uleak.o
	gcc -shared -Wl,-soname,libuleak.so.${VERSION_RELEASE} -o $@ $< ${LDFLAGS}

uleak.o: uleak.cpp
	g++ ${WFLAGS} ${OFLAGS} ${CFLAGS} -fPIC -c -o $@ $<

.PHONY: benchmark
benchmark: benchmark.cpp libuleak.a
	g++ ${WFLAGS} ${OFLAGS} ${CFLAGS} -o $@ $< libuleak.a ${LDFLAGS} -lrt
	./$@

.PHONY: clean
clean:
	rm -f libuleak.* uleak.o benchmark
