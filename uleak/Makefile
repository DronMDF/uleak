#
# Copyright (c) 2000-2008 Андрей Валяев (dron@infosec.ru)
# This code is licenced under the GPL3 (http://www.gnu.org/licenses/#GPL)
#


all: uleak.o

uleak.o: uleak.cpp
	g++ -Wall -Wextra -Weffc++ -Os -fomit-frame-pointer -c $< -o $@
