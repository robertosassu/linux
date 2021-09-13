# SPDX-License-Identifier: GPL-2.0
LDFLAGS += -lcrypto

CFLAGS += -O2 -Wall -Wl,-no-as-needed -g -I./ -I../../../../usr/include/ \
	  -L$(OUTPUT) -Wl,-rpath=./ -ggdb
LDLIBS += -lpthread

OVERRIDE_TARGETS = 1

TEST_GEN_PROGS = selftest manage_digest_lists
TEST_GEN_PROGS_EXTENDED = libcommon.so libcommon.a common.o

include ../lib.mk

$(OUTPUT)/libcommon.so: common.c
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/libcommon.a: common.o
	ar rcs libcommon.a common.o

$(OUTPUT)/selftest: selftest.c $(TEST_GEN_PROGS_EXTENDED)
	$(CC) $(CFLAGS) -DOUTPUT=\"$(OUTPUT)\" $< -o $@ $(LDFLAGS) -lcommon

$(OUTPUT)/manage_digest_lists: manage_digest_lists.c $(TEST_GEN_PROGS_EXTENDED)
	$(CC) $(CFLAGS) -static $< -o $@ $(LDFLAGS) -lcommon
