// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parse an rpm digest list (RPM package header).
 */

#define pr_fmt(fmt) "RPM DIGEST LIST: "fmt
#include <linux/module.h>

#include "parsers.h"

#define RPMTAG_FILEDIGESTS 1035
#define RPMTAG_FILEDIGESTALGO 5011

#define RPM_INT32_TYPE 4
#define RPM_STRING_ARRAY_TYPE 8

struct rpm_hdr {
	u32 magic;
	u32 reserved;
	u32 tags;
	u32 datasize;
} __packed;

struct rpm_entryinfo {
	s32 tag;
	u32 type;
	s32 offset;
	u32 count;
} __packed;

enum pgp_algos {
	DIGEST_ALGO_MD5		=  1,
	DIGEST_ALGO_SHA1	=  2,
	DIGEST_ALGO_RMD160	=  3,
	/* 4, 5, 6, and 7 are reserved. */
	DIGEST_ALGO_SHA256	=  8,
	DIGEST_ALGO_SHA384	=  9,
	DIGEST_ALGO_SHA512	= 10,
	DIGEST_ALGO_SHA224	= 11,
};

static const enum hash_algo pgp_algo_mapping[DIGEST_ALGO_SHA224 + 1] = {
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

/**
 * digest_list_parse_rpm - Parse an rpm digest list
 * @digest_cache: Digest cache
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function parses an rpm digest list.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_list_parse_rpm(struct digest_cache *digest_cache, const u8 *data,
			  size_t data_len)
{
	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};
	const struct rpm_hdr *hdr;
	const struct rpm_entryinfo *entry;
	u32 tags, max_tags, datasize;
	u32 digests_count, max_digests_count;
	u32 digests_offset, algo_offset;
	u32 digest_len, pkg_pgp_algo, i;
	bool algo_offset_set = false, digests_offset_set = false;
	enum hash_algo pkg_kernel_algo = HASH_ALGO_MD5;
	u8 rpm_digest[SHA512_DIGEST_SIZE];
	int ret;

	if (data_len < sizeof(*hdr)) {
		pr_debug("Not enough data for RPM header, current %ld, expected: %ld\n",
			 data_len, sizeof(*hdr));
		return -EINVAL;
	}

	if (memcmp(data, rpm_header_magic, sizeof(rpm_header_magic))) {
		pr_debug("RPM header magic mismatch\n");
		return -EINVAL;
	}

	hdr = (const struct rpm_hdr *)data;
	data += sizeof(*hdr);
	data_len -= sizeof(*hdr);

	tags = __be32_to_cpu(hdr->tags);
	max_tags = data_len / sizeof(*entry);

	/* Finite termination on tags loop. */
	if (tags > max_tags)
		return -EINVAL;

	datasize = __be32_to_cpu(hdr->datasize);
	if (datasize != data_len - tags * sizeof(*entry))
		return -EINVAL;

	pr_debug("Scanning %d RPM header sections\n", tags);
	for (i = 0; i < tags; i++) {
		if (data_len < sizeof(*entry))
			return -EINVAL;

		entry = (const struct rpm_entryinfo *)data;
		data += sizeof(*entry);
		data_len -= sizeof(*entry);

		switch (__be32_to_cpu(entry->tag)) {
		case RPMTAG_FILEDIGESTS:
			if (__be32_to_cpu(entry->type) != RPM_STRING_ARRAY_TYPE)
				return -EINVAL;

			digests_offset = __be32_to_cpu(entry->offset);
			digests_count = __be32_to_cpu(entry->count);
			digests_offset_set = true;

			pr_debug("Found RPMTAG_FILEDIGESTS at offset %u, count: %u\n",
				 digests_offset, digests_count);
			break;
		case RPMTAG_FILEDIGESTALGO:
			if (__be32_to_cpu(entry->type) != RPM_INT32_TYPE)
				return -EINVAL;

			algo_offset = __be32_to_cpu(entry->offset);
			algo_offset_set = true;

			pr_debug("Found RPMTAG_FILEDIGESTALGO at offset %u\n",
				 algo_offset);
			break;
		default:
			break;
		}
	}

	if (!digests_offset_set)
		return 0;

	if (algo_offset_set) {
		if (algo_offset >= data_len)
			return -EINVAL;

		if (data_len - algo_offset < sizeof(u32))
			return -EINVAL;

		pkg_pgp_algo = *(u32 *)&data[algo_offset];
		pkg_pgp_algo = __be32_to_cpu(pkg_pgp_algo);
		if (pkg_pgp_algo > DIGEST_ALGO_SHA224) {
			pr_debug("Unknown PGP algo %d\n", pkg_pgp_algo);
			return -EINVAL;
		}

		pkg_kernel_algo = pgp_algo_mapping[pkg_pgp_algo];
		if (pkg_kernel_algo >= HASH_ALGO__LAST) {
			pr_debug("Unknown mapping for PGP algo %d\n",
				 pkg_pgp_algo);
			return -EINVAL;
		}

		pr_debug("Found mapping for PGP algo %d: %s\n", pkg_pgp_algo,
			 hash_algo_name[pkg_kernel_algo]);
	}

	digest_len = hash_digest_size[pkg_kernel_algo];

	if (digests_offset > data_len)
		return -EINVAL;

	/* Worst case, every digest is a \0. */
	max_digests_count = data_len - digests_offset;

	/* Finite termination on digests_count loop. */
	if (digests_count > max_digests_count)
		return -EINVAL;

	ret = digest_cache_htable_init(digest_cache, digests_count,
				       pkg_kernel_algo);
	if (ret < 0)
		return ret;

	for (i = 0; i < digests_count; i++) {
		if (digests_offset == data_len)
			return -EINVAL;

		if (!data[digests_offset]) {
			digests_offset++;
			continue;
		}

		if (data_len - digests_offset < digest_len * 2 + 1)
			return -EINVAL;

		ret = hex2bin(rpm_digest, (const char *)&data[digests_offset],
			      digest_len);
		if (ret < 0) {
			pr_debug("Invalid hex format for digest %s\n",
				 &data[digests_offset]);
			return -EINVAL;
		}

		ret = digest_cache_htable_add(digest_cache, rpm_digest,
					      pkg_kernel_algo);
		if (ret < 0)
			return ret;

		digests_offset += digest_len * 2 + 1;
	}

	return ret;
}
