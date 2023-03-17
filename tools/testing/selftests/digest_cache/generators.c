// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generate digest lists for testing.
 */

#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <asm/byteorder.h>

#include "generators.h"
#include "../../../../include/uapi/linux/hash_info.h"
#include "../../../../include/uapi/linux/xattr.h"
#include "../../../../include/uapi/linux/tlv_digest_list.h"
#include "../../../../include/uapi/linux/tlv_parser.h"

int gen_tlv_list(int temp_dirfd, char *digest_list_filename,
		 enum hash_algo algo, int start_number, int num_digests,
		 enum tlv_failures failure)
{
	u64 _algo = __cpu_to_be64(algo);
	u8 digest[MAX_DIGEST_SIZE] = { 0 };
	int digest_len = hash_digest_size[algo];
	int digest_len_to_copy = digest_len;
	int ret, fd, i;

	struct tlv_data_entry algo_entry = {
		.field = __cpu_to_be64(DIGEST_LIST_ALGO),
		.length = __cpu_to_be64(sizeof(_algo)),
	};

	struct tlv_data_entry entry_digest = {
		.field = __cpu_to_be64(DIGEST_LIST_ENTRY_DIGEST),
		.length = __cpu_to_be64(digest_len),
	};

	struct tlv_hdr entry_hdr = {
		.data_type = __cpu_to_be64(DIGEST_LIST_ENTRY_DATA),
		._reserved = 0,
		.num_entries = __cpu_to_be64(1),
		.total_len = __cpu_to_be64(sizeof(entry_digest) + digest_len),
	};

	struct tlv_data_entry entry_entry = {
		.field = __cpu_to_be64(DIGEST_LIST_ENTRY),
		.length = __cpu_to_be64(sizeof(entry_hdr) +
					__be64_to_cpu(entry_hdr.total_len)),
	};

	struct tlv_hdr hdr = {
		.data_type = __cpu_to_be64(DIGEST_LIST_FILE),
		._reserved = 0,
		.num_entries = __cpu_to_be64(1 + num_digests),
		.total_len = __cpu_to_be64(sizeof(algo_entry) +
					   __be64_to_cpu(algo_entry.length) +
					   num_digests * (sizeof(entry_entry) +
					   __be64_to_cpu(entry_entry.length)))
	};

	switch (failure) {
	case TLV_FAILURE_ALGO_LEN:
		algo_entry.length = algo_entry.length / 2;
		break;
	case TLV_FAILURE_HDR_LEN:
		hdr.total_len--;
		break;
	case TLV_FAILURE_ALGO_MISMATCH:
		_algo = __cpu_to_be64(algo - 1);
		break;
	case TLV_FAILURE_NUM_DIGESTS:
		num_digests = 0;
		break;
	default:
		break;
	}

	fd = openat(temp_dirfd, digest_list_filename,
		    O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		return -errno;

	ret = write(fd, (u8 *)&hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		return -errno;

	ret = write(fd, (u8 *)&algo_entry, sizeof(algo_entry));
	if (ret != sizeof(algo_entry))
		return -errno;

	ret = write(fd, (u8 *)&_algo, sizeof(_algo));
	if (ret != sizeof(_algo))
		return -errno;

	*(u32 *)digest = start_number;

	for (i = 0; i < num_digests; i++) {
		ret = write(fd, (u8 *)&entry_entry, sizeof(entry_entry));
		if (ret != sizeof(entry_entry))
			return -errno;

		ret = write(fd, (u8 *)&entry_hdr, sizeof(entry_hdr));
		if (ret != sizeof(entry_hdr))
			return -errno;

		ret = write(fd, (u8 *)&entry_digest, sizeof(entry_digest));
		if (ret != sizeof(entry_digest))
			return -errno;

		ret = write(fd, digest, digest_len_to_copy);
		if (ret != digest_len_to_copy)
			return -errno;

		(*(u32 *)digest)++;
	}

	close(fd);
	return 0;
}

int gen_rpm_list(int temp_dirfd, char *digest_list_filename,
		 enum hash_algo algo, enum pgp_algos pgp_algo, int start_number,
		 int num_digests, enum rpm_failures failure)
{
	u32 _pgp_algo = __cpu_to_be32(pgp_algo);
	u8 digest[MAX_DIGEST_SIZE] = { 0 };
	char digest_str[MAX_DIGEST_SIZE * 2 + 1];
	struct rpm_hdr hdr;
	struct rpm_entryinfo algo_entry, digest_entry;
	int digest_len = hash_digest_size[algo];
	int ret, fd, d_len, i;

	d_len = hash_digest_size[algo] * 2 + 1;

	hdr.magic = __cpu_to_be32(0x8eade801);
	hdr.reserved = 0;
	hdr.tags = __cpu_to_be32(1);

	/*
	 * Skip the algo section, to ensure that the parser recognizes MD5 as
	 * the default hash algorithm.
	 */
	if (algo != HASH_ALGO_MD5)
		hdr.tags = __cpu_to_be32(2);

	hdr.datasize = __cpu_to_be32(d_len * num_digests);

	if (algo != HASH_ALGO_MD5)
		hdr.datasize = __cpu_to_be32(sizeof(u32) + d_len * num_digests);

	digest_entry.tag = __cpu_to_be32(RPMTAG_FILEDIGESTS);
	digest_entry.type = __cpu_to_be32(RPM_STRING_ARRAY_TYPE);
	digest_entry.offset = 0;
	digest_entry.count = __cpu_to_be32(num_digests);

	algo_entry.tag = __cpu_to_be32(RPMTAG_FILEDIGESTALGO);
	algo_entry.type = __cpu_to_be32(RPM_INT32_TYPE);
	algo_entry.offset = __cpu_to_be32(d_len * num_digests);
	algo_entry.count = __cpu_to_be32(1);

	switch (failure) {
	case RPM_FAILURE_WRONG_MAGIC:
		hdr.magic++;
		break;
	case RPM_FAILURE_BAD_DATA_OFFSET:
		algo_entry.offset = __cpu_to_be32(UINT_MAX);
		break;
	case RPM_FAILURE_WRONG_TAGS:
		hdr.tags = __cpu_to_be32(2 + 10);
		break;
	case RPM_FAILURE_WRONG_DIGEST_COUNT:
		/* We need to go beyond the algorithm, to fail. */
		digest_entry.count = __cpu_to_be32(num_digests + 5);
		break;
	case RPM_FAILURE_DIGEST_WRONG_TYPE:
		digest_entry.type = __cpu_to_be32(RPM_INT32_TYPE);
		break;
	default:
		break;
	}

	fd = openat(temp_dirfd, digest_list_filename,
		    O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		return -errno;

	ret = write(fd, (u8 *)&hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		return -errno;

	if (algo != HASH_ALGO_MD5) {
		ret = write(fd, (u8 *)&algo_entry, sizeof(algo_entry));
		if (ret != sizeof(algo_entry))
			return -errno;
	}

	ret = write(fd, (u8 *)&digest_entry, sizeof(digest_entry));
	if (ret != sizeof(digest_entry))
		return -errno;

	*(u32 *)digest = start_number;

	for (i = 0; i < num_digests; i++) {
		bin2hex(digest_str, digest, digest_len);

		ret = write(fd, (u8 *)digest_str, d_len);
		if (ret != d_len)
			return -errno;

		(*(u32 *)digest)++;
	}

	if (algo != HASH_ALGO_MD5) {
		ret = write(fd, (u8 *)&_pgp_algo, sizeof(_pgp_algo));
		if (ret != sizeof(_pgp_algo))
			return -errno;
	}

	close(fd);
	return 0;
}

int create_file(int temp_dirfd, char *filename, char *digest_list_filename)
{
	int ret = 0, fd;

	fd = openat(temp_dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		return -errno;

	if (!digest_list_filename)
		goto out;

	ret = fsetxattr(fd, XATTR_NAME_DIGEST_LIST, digest_list_filename,
			strlen(digest_list_filename) + 1, 0);
	if (ret == -1)
		ret = -errno;
out:
	close(fd);
	return ret;
}
