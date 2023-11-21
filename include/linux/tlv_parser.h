/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header file of TLV parser.
 */

#ifndef _LINUX_TLV_PARSER_H
#define _LINUX_TLV_PARSER_H

#include <uapi/linux/tlv_parser.h>

typedef int (*parse_callback)(void *, __u64, const __u8 *, __u64);

int tlv_parse_hdr(const __u8 **data, size_t *data_len, __u64 *parsed_data_type,
		  __u64 *parsed_num_entries, __u64 *parsed_total_len,
		  const char **data_types, __u64 num_data_types);
int tlv_parse_data(parse_callback callback, void *callback_data,
		   __u64 num_entries, const __u8 *data, size_t data_len,
		   const char **fields, __u64 num_fields);
int tlv_parse(__u64 expected_data_type, parse_callback callback,
	      void *callback_data, const __u8 *data, size_t data_len,
	      const char **data_types, __u64 num_data_types,
	      const char **fields, __u64 num_fields);

#endif /* _LINUX_TLV_PARSER_H */
