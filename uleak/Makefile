#
# Copyright (c) 2000-2008 Андрей Валяев (dron@infosec.ru)
# This code is licenced under the GPL3 (http://www.gnu.org/licenses/#GPL)
#

# Система номерации версий у меня своя.
VERSION_RELEASE = 0
VERSION_BETA = 0
VERSION_ALPHA = 1
VERSION_PATCH = 0

all: libuleak.a libuleak.so.${VERSION_RELEASE}.${VERSION_BETA}.${VERSION_ALPHA}

libuleak.a: uleak.o
	ar r $@ $<
	ranlib $@

libuleak.so.${VERSION_RELEASE}.${VERSION_BETA}.${VERSION_ALPHA} : uleak.o
	gcc -shared -Wl,-soname,libuleak.so.${VERSION_RELEASE} -o $@ $< -lc -lstdc++

uleak.o: uleak.cpp
	g++ -Wall -Wextra -Weffc++ -fPIC -c -o $@ $<

.PHONY: clean
clean:
	rm -f libuleak.* uleak.o