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
#define INVALID			1	/* Digest cache marked as invalid. */

/**
 * struct digest_cache_verif
 * @list: Linked list
 * @verif_id: Identifier of who verified the digest list
 * @data: Opaque data set by the digest list verifier
 *
 * This structure contains opaque data containing the result of verification
 * of the digest list by a verifier.
 */
struct digest_cache_verif {
	struct list_head list;
	char *verif_id;
	void *data;
};

/**
 * struct read_work - Structure to schedule reading a digest list
 * @work: Work structure
 * @file: File descriptor of the digest list to read
 * @data: Digest list data (updated)
 * @ret: Return value from kernel_read_file() (updated)
 *
 * This structure contains the necessary information to schedule reading a
 * digest list.
 */
struct read_work {
	struct work_struct work;
	struct file *file;
	void *data;
	int ret;
};

/**
 * struct digest_cache_entry - Entry of a digest cache hash table
 * @hnext: Pointer to the next element in the collision list
 * @digest: Stored digest
 *
 * This structure represents an entry of a digest cache hash table, storing a
 * digest.
 */
struct digest_cache_entry {
	struct hlist_node hnext;
	u8 digest[];
} __packed;

/**
 * struct htable - Hash table
 * @next: Next hash table in the linked list
 * @slots: Hash table slots
 * @num_slots: Number of slots
 * @num_digests: Number of digests stored in the hash table
 * @algo: Algorithm of the digests
 *
 * This structure is a hash table storing digests of file content or metadata.
 */
struct htable {
	struct list_head next;
	struct hlist_head *slots;
	unsigned int num_slots;
	u64 num_digests;
	enum hash_algo algo;
};

/**
 * struct digest_cache - Digest cache
 * @htables: Hash tables (one per algorithm)
 * @ref_count: Number of references to the digest cache
 * @path_str: Path of the digest list the digest cache was created from
 * @flags: Control flags
 * @verif_data: Verification data regarding the digest list
 * @verif_data_lock: Protect concurrent verification data additions
 *
 * This structure represents a cache of digests extracted from a digest list.
 */
struct digest_cache {
	struct list_head htables;
	atomic_t ref_count;
	char *path_str;
	unsigned long flags;
	struct list_head verif_data;
	spinlock_t verif_data_lock;
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
extern struct rw_semaphore default_path_sem;

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

static inline void digest_cache_to_file_sec(const struct file *file,
					    struct digest_cache *digest_cache)
{
	struct digest_cache **digest_cache_sec;

	digest_cache_sec = file->f_security + digest_cache_blob_sizes.lbs_file;
	*digest_cache_sec = digest_cache;
}

static inline struct digest_cache *
digest_cache_from_file_sec(const struct file *file)
{
	struct digest_cache **digest_cache_sec;

	digest_cache_sec = file->f_security + digest_cache_blob_sizes.lbs_file;
	return *digest_cache_sec;
}

/* main.c */
struct digest_cache *digest_cache_create(struct dentry *dentry,
					 struct path *digest_list_path,
					 char *path_str, char *filename);

/* htable.c */
int digest_cache_htable_init(struct digest_cache *digest_cache, u64 num_digests,
			     enum hash_algo algo);
int digest_cache_htable_add(struct digest_cache *digest_cache, u8 *digest,
			    enum hash_algo algo);
int digest_cache_htable_lookup(struct dentry *dentry,
			       struct digest_cache *digest_cache, u8 *digest,
			       enum hash_algo algo);
void digest_cache_htable_free(struct digest_cache *digest_cache);

/* populate.c */
int digest_cache_populate(struct digest_cache *digest_cache,
			  struct path *digest_list_path, char *path_str,
			  char *filename);

/* modsig.c */
size_t digest_cache_strip_modsig(__u8 *data, size_t data_len);

/* verif.c */
void digest_cache_verif_free(struct digest_cache *digest_cache);

#endif /* _DIGEST_CACHE_INTERNAL_H */
