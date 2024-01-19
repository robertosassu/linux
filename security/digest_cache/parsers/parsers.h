/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Digest list parsers.
 */

#include "../internal.h"

int digest_list_parse_tlv(struct digest_cache *digest_cache, const u8 *data,
			  size_t data_len);
