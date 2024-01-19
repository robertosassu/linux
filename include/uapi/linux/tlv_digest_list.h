/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Export definitions of the tlv digest list.
 */

#ifndef _UAPI_LINUX_TLV_DIGEST_LIST_H
#define _UAPI_LINUX_TLV_DIGEST_LIST_H

#include <linux/types.h>

#define FOR_EACH_DIGEST_LIST_TYPE(DIGEST_LIST_TYPE) \
	DIGEST_LIST_TYPE(DIGEST_LIST_FILE) \
	DIGEST_LIST_TYPE(DIGEST_LIST__LAST)

#define FOR_EACH_DIGEST_LIST_FIELD(DIGEST_LIST_FIELD) \
	DIGEST_LIST_FIELD(DIGEST_LIST_ALGO) \
	DIGEST_LIST_FIELD(DIGEST_LIST_ENTRY) \
	DIGEST_LIST_FIELD(DIGEST_LIST_FIELD__LAST)

#define FOR_EACH_DIGEST_LIST_ENTRY_TYPE(DIGEST_LIST_ENTRY_TYPE) \
	DIGEST_LIST_ENTRY_TYPE(DIGEST_LIST_ENTRY_DATA) \
	DIGEST_LIST_ENTRY_TYPE(DIGEST_LIST_ENTRY__LAST)

#define FOR_EACH_DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_FIELD) \
	DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_DIGEST) \
	DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_PATH) \
	DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_FIELD__LAST)

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

/**
 * enum digest_list_types - Types of digest list
 *
 * Enumerates the types of digest list to parse.
 */
enum digest_list_types {
	FOR_EACH_DIGEST_LIST_TYPE(GENERATE_ENUM)
};

/**
 * enum digest_list_fields - Digest list fields
 *
 * Enumerates the digest list fields.
 */
enum digest_list_fields {
	FOR_EACH_DIGEST_LIST_FIELD(GENERATE_ENUM)
};

/**
 * enum digest_list_entry_types - Types of data stored in DIGEST_LIST_ENTRY
 *
 * Enumerates the types of data stored in DIGEST_LIST_ENTRY (nested TLV data).
 */
enum digest_list_entry_types {
	FOR_EACH_DIGEST_LIST_ENTRY_TYPE(GENERATE_ENUM)
};

/**
 * enum digest_list_entry_fields - DIGEST_LIST_ENTRY fields
 *
 * Enumerates the DIGEST_LIST_ENTRY fields.
 */
enum digest_list_entry_fields {
	FOR_EACH_DIGEST_LIST_ENTRY_FIELD(GENERATE_ENUM)
};

#endif /* _UAPI_LINUX_TLV_DIGEST_LIST_H */
