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
#include <crypto/hash_info.h>

struct digest_cache;

/**
 * typedef digest_cache_found_t - Digest cache reference as numeric value
 *
 * This new type represents a digest cache reference that should not be put.
 */
typedef unsigned long digest_cache_found_t;

/**
 * digest_cache_from_found_t - Convert digest_cache_found_t to digest cache ptr
 * @found: digest_cache_found_t value
 *
 * Convert the digest_cache_found_t returned by digest_cache_lookup() to a
 * digest cache pointer, so that it can be passed to the other functions of the
 * API.
 *
 * Return: Digest cache pointer.
 */
static inline struct digest_cache *
digest_cache_from_found_t(digest_cache_found_t found)
{
	return (struct digest_cache *)found;
}

#ifdef CONFIG_SECURITY_DIGEST_CACHE
struct digest_cache *digest_cache_get(struct dentry *dentry);
void digest_cache_put(struct digest_cache *digest_cache);
digest_cache_found_t digest_cache_lookup(struct dentry *dentry,
					 struct digest_cache *digest_cache,
					 u8 *digest, enum hash_algo algo);
int digest_cache_verif_set(struct file *file, const char *verif_id, void *data,
			   size_t size);
void *digest_cache_verif_get(struct digest_cache *digest_cache,
			     const char *verif_id);

#else
static inline struct digest_cache *digest_cache_get(struct dentry *dentry)
{
	return NULL;
}

static inline void digest_cache_put(struct digest_cache *digest_cache)
{
}

static inline digest_cache_found_t
digest_cache_lookup(struct dentry *dentry, struct digest_cache *digest_cache,
		    u8 *digest, enum hash_algo algo)
{
	return 0UL;
}

static inline int digest_cache_verif_set(struct file *file,
					 const char *verif_id, void *data,
					 size_t size)
{
	return -EOPNOTSUPP;
}

static inline void *digest_cache_verif_get(struct digest_cache *digest_cache,
					   const char *verif_id)
{
	return NULL;
}

#endif /* CONFIG_SECURITY_DIGEST_CACHE */
#endif /* _LINUX_DIGEST_CACHE_H */
