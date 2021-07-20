#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

dpkg --add-architecture i386
apt update

apt install -y --no-install-recommends \
	linux-libc-dev:i386 \
	linux-libc-dev-i386-cross \
	libc6-dev-i386 \
	gcc-i686-linux-gnu \
	gcc \
	pkg-config:i386 \
	libssl-dev \
	openssl

ln -s /usr/include/i386-linux-gnu/openssl/opensslconf.h \
      /usr/include/openssl/opensslconf.h
