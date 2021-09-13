# SPDX-License-Identifier: GPL-2.0
LDFLAGS += -lcrypto

CFLAGS += -O2 -Wall -Wl,-no-as-needed -g -I./ -I../../../../usr/include/ \
	  -L$(OUTPUT) -Wl,-rpath=./ -ggdb
LDLIBS += -lpthread

OVERRIDE_TARGETS = 1

TEST_GEN_PROGS = selftest
TEST_GEN_PROGS_EXTENDED = libcommon.so

include ../lib.mk

$(OUTPUT)/libcommon.so: common.c
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/selftest: selftest.c $(TEST_GEN_PROGS_EXTENDED)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lcommon
