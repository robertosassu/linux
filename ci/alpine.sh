#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

apk update

apk add \
	$CC \
	make \
	musl-dev \
	openssl \
	openssl-dev \
	flex \
	bison \
	bc \
	bash \
	perl \
	libc-dev \
	linux-headers
