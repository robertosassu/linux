#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

# debian.*.sh must be run first
if [ "$ARCH" ]; then
	ARCH=":$ARCH"
	unset CC
else
	apt update
fi

apt="apt install -y --no-install-recommends"

$apt \
	$CC \
	libssl-dev$ARCH \
	make \
	openssl \
	flex \
	bison \
	bc \
	libc6-dev
