/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Public API of the digest_cache LSM.
 */

#ifndef _LINUX_DIGEST_CACHE_H
#define _LINUX_DIGEST_CACHE_H

#include <linux/fs.h>

struct digest_cache;

#ifdef CONFIG_SECURITY_DIGEST_CACHE
struct digest_cache *digest_cache_get(struct dentry *dentry);
void digest_cache_put(struct digest_cache *digest_cache);

#else
static inline struct digest_cache *digest_cache_get(struct dentry *dentry)
{
	return NULL;
}

static inline void digest_cache_put(struct digest_cache *digest_cache)
{
}

#endif /* CONFIG_SECURITY_DIGEST_CACHE */
#endif /* _LINUX_DIGEST_CACHE_H */
