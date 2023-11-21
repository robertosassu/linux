/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user space interface for the TLV parser.
 */

#ifndef _UAPI_LINUX_TLV_PARSER_H
#define _UAPI_LINUX_TLV_PARSER_H

#include <linux/types.h>

/*
 * TLV format:
 *
 * +-----------------+------------------+-----------------+
 * | data type (u64) | num fields (u64) | total len (u64) | # header
 * +--------------+--+---------+--------+---------+-------+
 * | field1 (u64) | len1 (u64) | value1 (u8 len1) |
 * +--------------+------------+------------------+
 * |     ...      |    ...     |        ...       |         # data
 * +--------------+------------+------------------+
 * | fieldN (u64) | lenN (u64) | valueN (u8 lenN) |
 * +--------------+------------+------------------+
 */

/**
 * struct tlv_hdr - Header of TLV format
 * @data_type: Type of data to parse
 * @num_entries: Number of data entries provided
 * @_reserved: Reserved for future use (must be equal to zero)
 * @total_len: Total length of the data blob, excluding the header
 *
 * This structure represents the header of the TLV data format.
 */
struct tlv_hdr {
	__u64 data_type;
	__u64 num_entries;
	__u64 _reserved;
	__u64 total_len;
} __attribute__((packed));

/**
 * struct tlv_data_entry - Data entry of TLV format
 * @field: Data field identifier
 * @length: Data length
 * @data: Data
 *
 * This structure represents a TLV entry of the data part of TLV data format.
 */
struct tlv_data_entry {
	__u64 field;
	__u64 length;
	__u8 data[];
} __attribute__((packed));

#endif /* _UAPI_LINUX_TLV_PARSER_H */
