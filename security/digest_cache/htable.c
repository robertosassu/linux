// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement hash table operations for the digest cache.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include <linux/namei.h>

#include "internal.h"

/**
 * digest_cache_hash_key - Compute hash key
 * @digest: Digest cache
 * @num_slots: Number of slots in the hash table
 *
 * This function computes a hash key based on the first two bytes of the
 * digest and the number of slots of the hash table.
 *
 * Return: Hash key.
 */
static inline unsigned int digest_cache_hash_key(u8 *digest,
						 unsigned int num_slots)
{
	/* Same as ima_hash_key() but parametrized. */
	return (digest[0] | digest[1] << 8) % num_slots;
}

/**
 * lookup_htable - Lookup a hash table
 * @digest_cache: Digest cache
 * @algo: Algorithm of the desired hash table
 *
 * This function searches the hash table for a given algorithm in the digest
 * cache.
 *
 * Return: A hash table if found, NULL otherwise.
 */
static struct htable *lookup_htable(struct digest_cache *digest_cache,
				    enum hash_algo algo)
{
	struct htable *h;

	list_for_each_entry(h, &digest_cache->htables, next)
		if (h->algo == algo)
			return h;

	return NULL;
}

/**
 * digest_cache_htable_init - Allocate and initialize the hash table
 * @digest_cache: Digest cache
 * @num_digests: Number of digests to add to the digest cache
 * @algo: Algorithm of the digests
 *
 * This function allocates and initializes the hash table for a given algorithm.
 * The number of slots depends on the number of digests to add to the digest
 * cache, and the constant CONFIG_DIGEST_CACHE_HTABLE_DEPTH stating the desired
 * average depth of the collision list.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_htable_init(struct digest_cache *digest_cache, u64 num_digests,
			     enum hash_algo algo)
{
	struct htable *h;
	int i;

	h = lookup_htable(digest_cache, algo);
	if (h)
		return 0;

	h = kmalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return -ENOMEM;

	h->num_slots = DIV_ROUND_UP(num_digests,
				    CONFIG_DIGEST_CACHE_HTABLE_DEPTH);
	h->slots = kmalloc_array(h->num_slots, sizeof(*h->slots), GFP_KERNEL);
	if (!h->slots) {
		kfree(h);
		return -ENOMEM;
	}

	for (i = 0; i < h->num_slots; i++)
		INIT_HLIST_HEAD(&h->slots[i]);

	h->num_digests = 0;
	h->algo = algo;

	list_add_tail(&h->next, &digest_cache->htables);

	pr_debug("Initialized hash table for digest list %s, digests: %llu, slots: %u, algo: %s\n",
		 digest_cache->path_str, num_digests, h->num_slots,
		 hash_algo_name[algo]);
	return 0;
}

/**
 * digest_cache_htable_add - Add a new digest to the digest cache
 * @digest_cache: Digest cache
 * @digest: Digest to add
 * @algo: Algorithm of digest
 *
 * This function, invoked by a digest list parser, adds a digest extracted
 * from a digest list to the digest cache.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_htable_add(struct digest_cache *digest_cache, u8 *digest,
			    enum hash_algo algo)
{
	struct htable *h;
	struct digest_cache_entry *entry;
	unsigned int key;
	int digest_len;

	h = lookup_htable(digest_cache, algo);
	if (!h) {
		pr_debug("No hash table for algorithm %s was found in digest cache %s, initialize one\n",
			 hash_algo_name[algo], digest_cache->path_str);
		return -ENOENT;
	}

	digest_len = hash_digest_size[algo];

	entry = kmalloc(sizeof(*entry) + digest_len, GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(entry->digest, digest, digest_len);

	key = digest_cache_hash_key(digest, h->num_slots);
	hlist_add_head(&entry->hnext, &h->slots[key]);
	h->num_digests++;
	pr_debug("Added digest %s:%*phN to digest cache %s, num of %s digests: %llu\n",
		 hash_algo_name[algo], digest_len, digest,
		 digest_cache->path_str, hash_algo_name[algo], h->num_digests);
	return 0;
}

/**
 * digest_cache_htable_lookup - Search a digest in the digest cache
 * @dentry: Dentry of the file whose digest is looked up
 * @digest_cache: Digest cache
 * @digest: Digest to search
 * @algo: Algorithm of the digest to search
 *
 * This function searches the passed digest and algorithm in the passed digest
 * cache.
 *
 * Return: Zero if the digest is found, -ENOENT if not.
 */
int digest_cache_htable_lookup(struct dentry *dentry,
			       struct digest_cache *digest_cache, u8 *digest,
			       enum hash_algo algo)
{
	struct digest_cache_entry *entry;
	struct htable *h;
	unsigned int key;
	int digest_len;
	int search_depth = 0;

	h = lookup_htable(digest_cache, algo);
	if (!h)
		return -ENOENT;

	digest_len = hash_digest_size[algo];
	key = digest_cache_hash_key(digest, h->num_slots);

	hlist_for_each_entry(entry, &h->slots[key], hnext) {
		if (!memcmp(entry->digest, digest, digest_len)) {
			pr_debug("Cache hit at depth %d for file %s, digest %s:%*phN in digest cache %s\n",
				 search_depth, dentry->d_name.name,
				 hash_algo_name[algo], digest_len, digest,
				 digest_cache->path_str);

			return 0;
		}

		search_depth++;
	}

	pr_debug("Cache miss for file %s, digest %s:%*phN in digest cache %s\n",
		 dentry->d_name.name, hash_algo_name[algo], digest_len, digest,
		 digest_cache->path_str);
	return -ENOENT;
}

/**
 * digest_cache_lookup - Search a digest in the digest cache
 * @dentry: Dentry of the file whose digest is looked up
 * @digest_cache: Digest cache
 * @digest: Digest to search
 * @algo: Algorithm of the digest to search
 *
 * This function calls digest_cache_htable_lookup() to search a digest in the
 * passed digest cache, obtained with digest_cache_get().
 *
 * It returns the digest cache reference as the digest_cache_found_t type, to
 * avoid that the digest cache is accidentally put. The digest_cache_found_t
 * type can be converted back to a digest cache pointer, by
 * calling digest_cache_from_found_t().
 *
 * Return: A positive digest_cache_found_t if the digest is found, zero if not.
 */
digest_cache_found_t digest_cache_lookup(struct dentry *dentry,
					 struct digest_cache *digest_cache,
					 u8 *digest, enum hash_algo algo)
{
	struct path digest_list_path;
	digest_cache_found_t found;
	int ret;

	if (!test_bit(IS_DIR, &digest_cache->flags)) {
		ret = digest_cache_htable_lookup(dentry, digest_cache, digest,
						 algo);
		return (!ret) ? (digest_cache_found_t)digest_cache : 0UL;
	}

	ret = kern_path(digest_cache->path_str, 0, &digest_list_path);
	if (ret < 0) {
		pr_debug("Cannot find path %s\n", digest_cache->path_str);
		return 0UL;
	}

	found = digest_cache_dir_lookup_digest(dentry, &digest_list_path,
					       digest_cache, digest, algo);
	path_put(&digest_list_path);
	return found;
}
EXPORT_SYMBOL_GPL(digest_cache_lookup);

/**
 * digest_cache_htable_free - Free the hash tables
 * @digest_cache: Digest cache
 *
 * This function removes all digests from all hash tables in the digest cache,
 * and frees the memory.
 */
void digest_cache_htable_free(struct digest_cache *digest_cache)
{
	struct htable *h, *h_tmp;
	struct digest_cache_entry *p;
	struct hlist_node *q;
	int i;

	list_for_each_entry_safe(h, h_tmp, &digest_cache->htables, next) {
		for (i = 0; i < h->num_slots; i++) {
			hlist_for_each_entry_safe(p, q, &h->slots[i], hnext) {
				hlist_del(&p->hnext);
				pr_debug("Removed digest %s:%*phN from digest cache %s\n",
					 hash_algo_name[h->algo],
					 hash_digest_size[h->algo], p->digest,
					 digest_cache->path_str);
				kfree(p);
			}
		}

		list_del(&h->next);
		kfree(h->slots);
		kfree(h);
	}
}
