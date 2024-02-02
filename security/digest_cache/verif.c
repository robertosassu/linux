// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Manage verification data regarding digest lists.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include "internal.h"

/**
 * free_verif - Free a digest_cache_verif structure
 * @verif: digest_cache_verif structure
 *
 * Free the space allocated for a digest_cache_verif structure.
 */
static void free_verif(struct digest_cache_verif *verif)
{
	kfree(verif->data);
	kfree(verif->verif_id);
	kfree(verif);
}

/**
 * digest_cache_verif_set - Set digest cache verification data
 * @file: File descriptor of the digest list being read to populate digest cache
 * @verif_id: Verifier ID
 * @data: Verification data (opaque)
 * @size: Size of @data
 *
 * This function lets a verifier supply verification data about a digest list
 * being read to populate the digest cache.
 *
 * Return: Zero on success, -ENOMEM if out of memory.
 */
int digest_cache_verif_set(struct file *file, const char *verif_id, void *data,
			   size_t size)
{
	struct digest_cache *digest_cache = digest_cache_from_file_sec(file);
	struct digest_cache_verif *new_verif;

	/*
	 * All allocations must be atomic (non-sleepable) since kprobe does not
	 * allow otherwise (kprobe is needed for testing).
	 */
	new_verif = kzalloc(sizeof(*new_verif), GFP_ATOMIC);
	if (!new_verif)
		return -ENOMEM;

	new_verif->verif_id = kstrdup(verif_id, GFP_ATOMIC);
	if (!new_verif->verif_id) {
		free_verif(new_verif);
		return -ENOMEM;
	}

	new_verif->data = kmemdup(data, size, GFP_ATOMIC);
	if (!new_verif->data) {
		free_verif(new_verif);
		return -ENOMEM;
	}

	spin_lock(&digest_cache->verif_data_lock);
	list_add_tail_rcu(&new_verif->list, &digest_cache->verif_data);
	spin_unlock(&digest_cache->verif_data_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(digest_cache_verif_set);

/**
 * digest_cache_verif_get - Get digest cache verification data
 * @digest_cache: Digest cache
 * @verif_id: Verifier ID
 *
 * This function returns the verification data previously set by a verifier
 * with digest_cache_verif_set().
 *
 * Return: Verification data if found, NULL otherwise.
 */
void *digest_cache_verif_get(struct digest_cache *digest_cache,
			     const char *verif_id)
{
	struct digest_cache_verif *verif;
	void *verif_data = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(verif, &digest_cache->verif_data, list) {
		if (!strcmp(verif->verif_id, verif_id)) {
			verif_data = verif->data;
			break;
		}
	}
	rcu_read_unlock();

	return verif_data;
}
EXPORT_SYMBOL_GPL(digest_cache_verif_get);

/**
 * digest_cache_verif_free - Free all digest_cache_verif structures
 * @digest_cache: Digest cache
 *
 * This function frees the space allocated for all digest_cache_verif
 * structures in the digest cache.
 */
void digest_cache_verif_free(struct digest_cache *digest_cache)
{
	struct digest_cache_verif *p, *q;

	/* No need to lock, called when nobody else has a digest cache ref. */
	list_for_each_entry_safe(p, q, &digest_cache->verif_data, list) {
		list_del(&p->list);
		free_verif(p);
	}
}
