/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user space interface for user asymmetric keys and signatures.
 */

#ifndef _UAPI_LINUX_UASYM_PARSER_H
#define _UAPI_LINUX_UASYM_PARSER_H

#include <linux/types.h>
#include <linux/pub_key_info.h>

#define FOR_EACH_DATA_TYPE(DATA_TYPE) \
	DATA_TYPE(TYPE_KEY) \
	DATA_TYPE(TYPE_SIG) \
	DATA_TYPE(TYPE__LAST)

#define FOR_EACH_FIELD(FIELD) \
	FIELD(KEY_PUB) \
	FIELD(KEY_ALGO) \
	FIELD(KEY_KID0) \
	FIELD(KEY_KID1) \
	FIELD(KEY_KID2) \
	FIELD(KEY_DESC) \
	FIELD(SIG_S) \
	FIELD(SIG_KEY_ALGO) \
	FIELD(SIG_HASH_ALGO) \
	FIELD(SIG_ENC) \
	FIELD(SIG_KID0) \
	FIELD(SIG_KID1) \
	FIELD(SIG_KID2) \
	FIELD(SIG_DATA_END) \
	FIELD(FIELD__LAST)

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

/**
 * enum data_types - Type of data to parse
 *
 * Enumerates the type of data to parse.
 */
enum data_types {
	FOR_EACH_DATA_TYPE(GENERATE_ENUM)
};

/**
 * enum fields - Data fields
 *
 * Enumerates the data fields. Some belongs to keys, some to signatures.
 */
enum fields {
	FOR_EACH_FIELD(GENERATE_ENUM)
};

#endif /* _UAPI_LINUX_UASYM_PARSER_H */
