/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of common_user.c.
 */

#include <linux/types.h>
#include <stddef.h>

#include "common.h"

extern const enum hash_algo pgp_algo_mapping[DIGEST_ALGO_SHA224 + 1];

char *bin2hex(char *dst, const void *src, size_t count);
