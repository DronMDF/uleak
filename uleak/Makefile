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
OFLAGS=-O2 -ggdb3
# поддержки 64-х бит пока нету...
CFLAGS=-m32
LDFLAGS=-lc -lstdc++

ifneq ("${wildcard /usr/lib/libunwind-x86.*}x", "x")
	CFLAGS+=-DLIBUNWIND
	LDFLAGS+=-lunwind -lunwind-generic
endif

all: libuleak.a libuleak.so.${VERSION}

libuleak.a: uleak.o
	ar r $@ $<
	ranlib $@

libuleak.so.${VERSION} : uleak.o
	gcc -shared -Wl,-soname,libuleak.so.${VERSION_RELEASE} ${CFLAGS} -o $@ $< ${LDFLAGS}

uleak.o: uleak.cpp
	g++ ${WFLAGS} ${OFLAGS} ${CFLAGS} -fPIC -c -o $@ $<

benchmark: benchmark.cpp libuleak.a
	g++ ${WFLAGS} ${OFLAGS} ${CFLAGS} -o $@ $< libuleak.a ${LDFLAGS} -lrt
	./$@

.PHONY: clean
clean:
	rm -f libuleak.* uleak.o benchmark
