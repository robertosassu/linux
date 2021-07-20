#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

zypper --non-interactive install --force-resolution --no-recommends \
	$CC \
	libopenssl-devel \
	make \
	openssl \
	flex \
	bison \
	bc \
	perl \
	diffutils
