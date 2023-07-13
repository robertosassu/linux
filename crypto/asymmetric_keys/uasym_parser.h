/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header file of user asymmetric keys and signatures.
 */

#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>

#include <uapi/linux/uasym_parser.h>

#define kenter(FMT, ...) \
	pr_debug("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_debug("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

extern const char *data_types_str[];
extern const char *fields_str[];

int parse_key_algo(const char **pkey_algo, enum fields field,
		   const u8 *field_data, u64 field_data_len);
int parse_key_kid(struct asymmetric_key_id **id, enum fields field,
		  const u8 *field_data, u64 field_data_len);
