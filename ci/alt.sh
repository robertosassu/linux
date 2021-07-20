#!/bin/sh -ex
# SPDX-License-Identifier: GPL-2.0-only
#
# Install build env for ALT Linux

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

apt-get update -y

# rpm-build brings basic build environment with gcc, make, autotools, etc.
apt-get install -y \
		$CC \
		libssl-devel \
		openssl \
		make \
		flex \
		bison \
		bc
