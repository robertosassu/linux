/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * DIGLIM definitions exported to user space, useful for generating digest
 * lists.
 */

#ifndef _UAPI__LINUX_DIGLIM_H
#define _UAPI__LINUX_DIGLIM_H

#include <linux/types.h>
#include <linux/hash_info.h>

enum compact_types { COMPACT_PARSER, COMPACT_FILE, COMPACT_METADATA,
		     COMPACT_DIGEST_LIST, COMPACT__LAST };

enum compact_modifiers { COMPACT_MOD_IMMUTABLE, COMPACT_MOD__LAST };

enum compact_actions { COMPACT_ACTION_IMA_MEASURED,
		       COMPACT_ACTION_IMA_APPRAISED,
		       COMPACT_ACTION_IMA_APPRAISED_DIGSIG,
		       COMPACT_ACTION__LAST };

enum ops { DIGEST_LIST_ADD, DIGEST_LIST_DEL, DIGEST_LIST_OP__LAST };

/**
 * struct compact_list_hdr - header of the following concatenated digests
 * @version: version of the digest list
 * @_reserved: field set to zero and reserved for future use
 * @type: type of digest list among enum compact_types
 * @modifiers: bitmask of attributes with pos defined in enum compact_modifiers
 * @algo: digest algo among enum hash_algo in include/uapi/linux/hash_info.h
 * @count: number of digests
 * @datalen: length of concatenated digests
 *
 * A digest list is a set of blocks composed by struct compact_list_hdr and
 * the following concatenated digests.
 */
struct compact_list_hdr {
	__u8 version;
	__u8 _reserved;
	__le16 type;
	__le16 modifiers;
	__le16 algo;
	__le32 count;
	__le32 datalen;
} __packed;
#endif /*_UAPI__LINUX_DIGLIM_H*/
