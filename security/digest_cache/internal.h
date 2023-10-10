/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Internal header of the digest_cache LSM.
 */

#ifndef _DIGEST_CACHE_INTERNAL_H
#define _DIGEST_CACHE_INTERNAL_H

#include <linux/lsm_hooks.h>
#include <linux/digest_cache.h>

/* Digest cache bits in flags. */
#define INIT_IN_PROGRESS	0	/* Digest cache being initialized. */

/**
 * struct digest_cache - Digest cache
 * @ref_count: Number of references to the digest cache
 * @path_str: Path of the digest list the digest cache was created from
 * @flags: Control flags
 *
 * This structure represents a cache of digests extracted from a digest list.
 */
struct digest_cache {
	atomic_t ref_count;
	char *path_str;
	unsigned long flags;
};

/**
 * struct digest_cache_security - Digest cache pointers in inode security blob
 * @dig_owner: Digest cache created from this inode
 * @dig_owner_mutex: Protects @dig_owner
 * @dig_user: Digest cache requested for this inode
 * @dig_user_mutex: Protects @dig_user
 *
 * This structure contains references to digest caches, protected by their
 * respective mutex.
 */
struct digest_cache_security {
	struct digest_cache *dig_owner;
	struct mutex dig_owner_mutex;
	struct digest_cache *dig_user;
	struct mutex dig_user_mutex;
};

extern struct lsm_blob_sizes digest_cache_blob_sizes;
extern char *default_path_str;

static inline struct digest_cache_security *
digest_cache_get_security(const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;

	return inode->i_security + digest_cache_blob_sizes.lbs_inode;
}

static inline struct digest_cache *
digest_cache_ref(struct digest_cache *digest_cache)
{
	atomic_inc(&digest_cache->ref_count);
	pr_debug("Ref (+) digest cache %s (ref count: %d)\n",
		 digest_cache->path_str, atomic_read(&digest_cache->ref_count));
	return digest_cache;
}

static inline struct digest_cache *
digest_cache_unref(struct digest_cache *digest_cache)
{
	bool ref_is_zero = atomic_dec_and_test(&digest_cache->ref_count);

	pr_debug("Ref (-) digest cache %s (ref count: %d)\n",
		 digest_cache->path_str, atomic_read(&digest_cache->ref_count));
	return (ref_is_zero) ? digest_cache : NULL;
}

/* main.c */
struct digest_cache *digest_cache_create(struct dentry *dentry,
					 struct path *digest_list_path,
					 char *path_str, char *filename);

#endif /* _DIGEST_CACHE_INTERNAL_H */
