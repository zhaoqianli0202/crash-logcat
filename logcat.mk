#
# Copyright (C) 2009, 2011, 2013 David Anderson
# Copyright (C) 2009, 2011, 2013 Red Hat, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

TARGET=ARM64
ARCH_CFLAGS=-D_SYS_UCONTEXT_H=1
ARCH=SUPPORTED

ifeq ($(shell /bin/ls /usr/include/crash/defs.h 2>/dev/null), /usr/include/crash/defs.h)
  INCDIR=/usr/include/crash
endif
ifeq ($(shell /bin/ls ../defs.h 2> /dev/null), ../defs.h)
  INCDIR=..
endif
ifeq ($(shell /bin/ls ./defs.h 2> /dev/null), ./defs.h)
  INCDIR=.
endif

all: logcat.so
	
logcat.so: $(INCDIR)/defs.h logcat.c 
	gcc -Wall -g -I$(INCDIR) -shared -rdynamic -o logcat.so logcat.c -fPIC -D$(TARGET) $(TARGET_CFLAGS) $(GDB_FLAGS)
