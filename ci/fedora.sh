#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -e

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

yum -y install \
	$CC \
	make \
	openssl \
	openssl-devel \
	flex \
	bison \
	bc \
	perl \
	diffutils

if [ "$DEVTOOLSET" = "yes" ]; then
	yum -y install centos-release-scl
	yum -y install devtoolset-10
fi
