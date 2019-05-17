############## COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE #############
## Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          #
## All Rights Reserved                                                      #
## The source code form of this Open Source Project components              #
## is subject to the terms of the BSD-2-Clause-Patent.                      #
## You can redistribute it and/or modify it under the terms of              #
## the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) #
## See COPYING file/LICENSE file for more details.                          #
#############################################################################


#SRCDIRS :=
#LIBRARY_DIRS :=
#DOXYGEN_CONFIG := doxyfile
PLATFORM_LIB := libplatform_map.so
UBUS_LIB := libubus_map_tch.so


ifeq ($(PLATFORM),openwrt)
LIBINCLUDE_DIRS := ./include
LIB_LIBRARIES+= -luci -llua -lm -ldl -ljansson -lubus -lubox -luv -ltransformer
LIBSRC+=$(wildcard src/*.c)
UBUSLIBSRC+=$(wildcard src/ubus_map/*.c)

LIBCFLAGS := -fPIC -g -Wall -Werror #-pedantic -Wall -Wextra
LDFLAGS+= -shared
EXTRA_FLAGS = -DOPENWRT
endif

LIBINCLUDE_FLAGS=$(foreach includedir, $(LIBINCLUDE_DIRS), -I$(includedir))

LIBOBJFILES = $(LIBSRC:.c=.o)
UBUS_LIBOBJFILES = $(UBUSLIBSRC:.c=.o)

LIBCFLAGS+=$(EXTRA_FLAGS)

CFLAGS +=$(LIBCFLAGS)
CFLAGS += -D_XOPEN_SOURCE=700
CFLAGS += -D_DEFAULT_SOURCE

ifeq ($(ENDIANNESS), big)
    CFLAGS       += -D_HOST_IS_BIG_ENDIAN_=1
else
    CFLAGS       += -D_HOST_IS_LITTLE_ENDIAN_=1
endif

INCLUDE_FLAGS+=$(LIBINCLUDE_FLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

all: $(LIBOBJFILES) $(UBUS_LIBOBJFILES)
	$(CC) $(LIBOBJFILES) -o $(PLATFORM_LIB) $(LDFLAGS) $(LIB_LIBRARIES)
	$(CC) $(UBUS_LIBOBJFILES) -o $(UBUS_LIB) $(LDFLAGS) $(LIB_LIBRARIES)

#Clean files
clean:
	rm -f $(LIBOBJFILES) rm -f $(PLATFORM_LIB)
	rm -f $(UBUS_LIBOBJFILES) rm -f $(UBUS_LIB)

#Make Doxygen files
#doxygen:
#	cd docs && \
#	doxygen $(DOXYGEN_CONFIG)

#Clean Doxygen files
#clean_doxygen:
#	rm -rf docs/html
#	rm -rf docs/latex
