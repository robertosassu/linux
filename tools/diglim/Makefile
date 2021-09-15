# SPDX-License-Identifier: GPL-2.0

CC := $(CROSS_COMPILE)gcc
CFLAGS += -O2 -Wall -g -I./ -I$(DESTDIR)/usr/include -ggdb

PROGS := compact_gen rpm_gen upload_digest_lists
PROGS_EXTENDED := common.o

all: $(PROGS)

clean:
	rm -fr $(PROGS) $(PROGS_EXTENDED)

common.o: common.c
	$(CC) -c $(CFLAGS) $< -o $@

compact_gen: compact_gen.c $(PROGS_EXTENDED)
	$(CC) $(CFLAGS) $< $(PROGS_EXTENDED) -o $@ $(LDFLAGS) -lcrypto

rpm_gen: rpm_gen.c $(PROGS_EXTENDED)
	$(CC) $(CFLAGS) $< $(PROGS_EXTENDED) -o $@ $(LDFLAGS) -lrpm -lrpmio

upload_digest_lists: upload_digest_lists.c
	$(CC) $(CFLAGS) -static $< -o $@ $(LDFLAGS)
