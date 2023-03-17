// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Add common code in user space for testing the digest_cache LSM.
 */

#include <stddef.h>

#include "common_user.h"

static const char hex_asc[] = "0123456789abcdef";

#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

const enum hash_algo pgp_algo_mapping[DIGEST_ALGO_SHA224 + 1] = {
	[DIGEST_ALGO_MD5]	= HASH_ALGO_MD5,
	[DIGEST_ALGO_SHA1]	= HASH_ALGO_SHA1,
	[DIGEST_ALGO_RMD160]	= HASH_ALGO_RIPE_MD_160,
	[4]			= HASH_ALGO__LAST,
	[5]			= HASH_ALGO__LAST,
	[6]			= HASH_ALGO__LAST,
	[7]			= HASH_ALGO__LAST,
	[DIGEST_ALGO_SHA256]	= HASH_ALGO_SHA256,
	[DIGEST_ALGO_SHA384]	= HASH_ALGO_SHA384,
	[DIGEST_ALGO_SHA512]	= HASH_ALGO_SHA512,
	[DIGEST_ALGO_SHA224]	= HASH_ALGO_SHA224,
};

static inline char *hex_byte_pack(char *buf, unsigned char byte)
{
	*buf++ = hex_asc_hi(byte);
	*buf++ = hex_asc_lo(byte);
	return buf;
}

char *bin2hex(char *dst, const void *src, size_t count)
{
	const unsigned char *_src = src;

	while (count--)
		dst = hex_byte_pack(dst, *_src++);
	return dst;
}
