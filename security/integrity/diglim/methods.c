// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Functions to manage digest lists.
 */

#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/fault-inject.h>

#include "diglim.h"
#include "../integrity.h"

/* Define a cache for each object type. */
static struct kmem_cache *digest_list_item_cache __read_mostly;
static struct kmem_cache *digest_list_item_ref_cache __read_mostly;
static struct kmem_cache *digest_item_cache __read_mostly;

/* Define a hash table for each digest type. */
struct h_table diglim_htable[COMPACT__LAST] = {{
	.queue[0 ... DIGLIM_HTABLE_SIZE - 1] = HLIST_HEAD_INIT
}};

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
static DECLARE_FAULT_ATTR(fail_diglim);

static int __init fail_diglim_debugfs(void)
{
	struct dentry *dir = fault_create_debugfs_attr("fail_diglim", NULL,
						       &fail_diglim);

	return PTR_ERR_OR_ZERO(dir);
}

static inline bool should_fail_diglim(void)
{
	return should_fail(&fail_diglim, 1);
}

late_initcall(fail_diglim_debugfs);
#else
static inline bool should_fail_diglim(void)
{
	return false;
}
#endif

/**
 * __digest_lookup - lookup digest and return associated modifiers and actions
 * @digest: digest to lookup
 * @algo: digest algorithm
 * @type: type of digest to lookup (e.g. file, metadata)
 * @modifiers: modifiers (attributes) associated to the found digest
 * @actions: actions performed by IMA on the digest list containing the digest
 *
 * This function searches the given digest in the hash table depending on the
 * passed type and sets the modifiers and actions associated to the digest, if
 * the pointers are not NULL.
 *
 * This function is not intended for external use, as the returned digest item
 * could be freed at any time after it has been returned.
 * diglim_digest_get_info() should be used instead by external callers, as it
 * only returns the modifiers and the actions associated to the digest at the
 * time the digest is searched.
 *
 * RCU protects both the hash table and the linked list of references to the
 * digest lists containing the found digest.
 *
 * Return: a digest_item structure if the digest is found, NULL otherwise.
 */
struct digest_item *__digest_lookup(u8 *digest, enum hash_algo algo,
				    enum compact_types type, u16 *modifiers,
				    u8 *actions)
{
	struct digest_item *d = NULL;
	struct digest_list_item_ref *ref;
	int digest_len = hash_digest_size[algo];
	unsigned int key = hash_key(digest);
	bool found = false;

	rcu_read_lock();
	hlist_for_each_entry_rcu(d, &diglim_htable[type].queue[key], hnext) {
		list_for_each_entry_rcu(ref, &d->refs, list) {
			if (get_algo_ref(ref) != algo ||
			    memcmp(get_digest_ref(ref), digest, digest_len))
				break;

			found = true;

			/* There is no need to scan all digest list refs. */
			if (!modifiers || !actions)
				break;

			/*
			 * The resulting modifiers and actions are the OR of the
			 * modifiers and actions for each digest list.
			 */
			*modifiers |= get_hdr_ref(ref)->modifiers;
			*actions |= ref->digest_list->actions;
		}

		if (found)
			break;
	}

	rcu_read_unlock();
	return d;
}

/**
 * diglim_digest_get_info - lookup digest and return modifiers and actions
 * @digest: digest to lookup
 * @algo: digest algorithm
 * @type: type of digest to lookup (e.g. file, metadata)
 * @modifiers: modifiers (attributes) associated to the found digest
 * @actions: actions performed by IMA on the digest lists containing the digest
 *
 * This function searches the given digest in the hash table depending on the
 * passed type and sets the modifiers and actions associated to the digest, if
 * the pointers are not NULL.
 *
 * This function is safe for external use, as it does not return pointers of
 * objects that can be freed without the caller notices it.
 *
 * Return: 0 if the digest is found, -ENOENT otherwise.
 */
int diglim_digest_get_info(u8 *digest, enum hash_algo algo,
			   enum compact_types type, u16 *modifiers, u8 *actions)
{
	struct digest_item *d;

	d = __digest_lookup(digest, algo, type, modifiers, actions);
	if (!d)
		return -ENOENT;

	return 0;
}

/**
 * digest_list_ref_add - add reference to a digest list
 * @d: digest a new reference is added to
 * @digest_list: digest list whose reference is being added
 * @digest_offset: offset of the digest in the buffer of the digest list
 * @hdr_offset: offset of the header within the digest list the digest refers to
 *
 * This function adds a new reference to an existing digest list for a given
 * digest. The reference is described by the digest_list_item_ref structure and
 * consists of a pointer of the digest list, the offset of the digest to the
 * beginning of the digest list buffer and the offset of the header the digest
 * refers to (each digest list might be composed of several digest blocks, each
 * prefixed by a header describing the attributes of those digests).
 *
 * Return: 0 if a new digest list reference was successfully added, a negative
 * value otherwise.
 */
static int digest_list_ref_add(struct digest_item *d,
			       struct digest_list_item *digest_list,
			       loff_t digest_offset, loff_t hdr_offset)
{
	struct digest_list_item_ref *new_ref = NULL;
	u8 *digest = get_digest(digest_list, digest_offset, hdr_offset);
	enum hash_algo algo = get_algo(digest_list, digest_offset, hdr_offset);
	int digest_len = hash_digest_size[algo];

	/* Allocate a new reference. */
	if (!should_fail_diglim())
		new_ref = kmem_cache_alloc(digest_list_item_ref_cache,
					   GFP_KERNEL);
	if (!new_ref) {
		print_hex_dump(KERN_ERR, "digest list ref allocation failed: ",
			       DUMP_PREFIX_NONE, digest_len, 1, digest,
			       digest_len, true);
		return -ENOMEM;
	}

	/* Set the new reference. */
	new_ref->digest_list = digest_list;
	/* Converting loff_t -> u32 is fine as long as the digest list < 4G. */
	new_ref->digest_offset = digest_offset;
	new_ref->hdr_offset = hdr_offset;

	list_add_tail_rcu(&new_ref->list, &d->refs);

	print_hex_dump_debug("add digest list ref: ", DUMP_PREFIX_NONE,
			     digest_len, 1, digest, digest_len, true);
	return 0;
}

/**
 * digest_list_ref_del - del reference to a digest list
 * @d: digest a reference is deleted from
 * @digest_list: digest list whose reference is being deleted
 * @digest_offset: offset of the digest in the buffer of the digest list
 * @hdr_offset: offset of the header within the digest list the digest refers to
 *
 * This function searches the reference to an already loaded digest list in the
 * linked list of references stored for each digest item. If the reference is
 * found (if not, it is a bug), the function deletes it from the linked list.
 */
static void digest_list_ref_del(struct digest_item *d,
				struct digest_list_item *digest_list,
				loff_t digest_offset, loff_t hdr_offset)
{
	struct digest_list_item_ref *ref;
	u8 *digest = get_digest(digest_list, digest_offset, hdr_offset);
	enum hash_algo algo = get_algo(digest_list, digest_offset, hdr_offset);
	int digest_len = hash_digest_size[algo];

	/* Search for a digest list reference. */
	list_for_each_entry(ref, &d->refs, list)
		if (ref->digest_list == digest_list)
			break;

	if (!ref) {
		print_hex_dump(KERN_ERR, "digest list ref not found: ",
			       DUMP_PREFIX_NONE, digest_len, 1, digest,
			       digest_len, true);
		return;
	}

	list_del_rcu(&ref->list);
	kmem_cache_free(digest_list_item_ref_cache, ref);

	print_hex_dump_debug("del digest list ref: ", DUMP_PREFIX_NONE,
			     digest_len, 1, digest, digest_len, true);
}

/**
 * digest_add - add a new digest
 * @digest: digest in binary form
 * @algo: digest algorithm
 * @type: digest type
 * @digest_list: digest list the new digest belongs to
 * @digest_offset: offset of the digest in the buffer of the digest list
 * @hdr_offset: offset of the header within the digest list the digest refers to
 *
 * This function first searches if the digest is already in the hash table for
 * the given type. The digest is searched by comparing the passed digest and
 * algorithm with the digest obtained from the first digest list reference
 * (buffer + digest_offset), or from the digest field of a digest list item,
 * for a digest list.
 *
 * If the digest exists, only a new reference is added (there might be multiple
 * references to the same digest list).
 *
 * If the digest is not found, a new digest item is allocated and a reference to
 * the passed digest list is added to that item. The digest item is finally
 * added to the hash table for the given type.
 *
 * Proper locking must be provided by the caller.
 *
 * Return: a new or the found digest item on success, an error pointer
 * otherwise.
 */
struct digest_item *digest_add(u8 *digest, enum hash_algo algo,
			       enum compact_types type,
			       struct digest_list_item *digest_list,
			       loff_t digest_offset, loff_t hdr_offset)
{
	int digest_len = hash_digest_size[algo];
	struct digest_item *d;
	int ret;

	/* Search the digest. */
	d = __digest_lookup(digest, algo, type, NULL, NULL);
	if (d) {
		/*
		 * Add a new digest list reference to the existing digest item.
		 */
		ret = digest_list_ref_add(d, digest_list, digest_offset,
					  hdr_offset);
		if (ret < 0)
			return ERR_PTR(ret);

		print_hex_dump_debug("digest add duplicate: ", DUMP_PREFIX_NONE,
				     digest_len, 1, digest, digest_len, true);
		return d;
	}

	/* Allocate a new digest item. */
	if (!should_fail_diglim())
		d = kmem_cache_alloc(digest_item_cache, GFP_KERNEL);
	if (!d) {
		print_hex_dump_debug("digest allocation failed: ",
				     DUMP_PREFIX_NONE, digest_len, 1, digest,
				     digest_len, true);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&d->refs);

	/* Add a new digest list reference to the new digest item. */
	ret = digest_list_ref_add(d, digest_list, digest_offset, hdr_offset);
	if (ret < 0) {
		kmem_cache_free(digest_item_cache, d);
		return ERR_PTR(ret);
	}

	/* Add the new digest item to the hash table for the given type. */
	hlist_add_head_rcu(&d->hnext,
			   &diglim_htable[type].queue[hash_key(digest)]);
	diglim_htable[type].len++;

	print_hex_dump_debug("digest add: ", DUMP_PREFIX_NONE, digest_len, 1,
			     digest, digest_len, true);
	return d;
}

/**
 * digest_del - delete a digest with one reference, or just a reference
 * @digest: digest in binary form
 * @algo: digest algorithm
 * @type: digest type
 * @digest_list: digest list the digest belongs to
 * @digest_offset: offset of the digest in the buffer of the digest list
 * @hdr_offset: offset of the header within the digest list the digest refers to
 *
 * This function is called when a digest list is being removed. The digest is
 * first searched in the hash table for the given type. If it is found (if not,
 * it is a bug, because digest lists can be deleted only if they were added
 * previously), a reference of the passed digest list is deleted from the linked
 * list of references of the digest item.
 *
 * If the last reference was deleted, the digest item is also deleted and
 * removed from the hash table.
 *
 * Proper locking must be provided by the caller.
 */
void digest_del(u8 *digest, enum hash_algo algo, enum compact_types type,
		struct digest_list_item *digest_list, loff_t digest_offset,
		loff_t hdr_offset)
{
	struct digest_item *d;
	int digest_len = hash_digest_size[algo];

	/* Search the digest. */
	d = __digest_lookup(digest, algo, type, NULL, NULL);
	if (!d) {
		print_hex_dump(KERN_ERR, "digest not found: ", DUMP_PREFIX_NONE,
			       digest_len, 1, digest, digest_len, true);
		return;
	}

	/* Delete a reference of the passed digest list. */
	digest_list_ref_del(d, digest_list, digest_offset, hdr_offset);

	print_hex_dump_debug(!list_empty(&d->refs) ?
			     "digest del duplicate: " : "digest del: ",
			     DUMP_PREFIX_NONE, digest_len, 1, digest,
			     digest_len, true);

	/* Return if there are still references. */
	if (!list_empty(&d->refs))
		return;

	/*
	 * Remove the digest item from the hash table and free it if there are
	 * no more references left.
	 */
	hlist_del_rcu(&d->hnext);
	diglim_htable[type].len--;
	kmem_cache_free(digest_item_cache, d);
}

static void digest_list_free(struct digest_list_item *digest_list)
{
	kfree(digest_list->label);
	kfree(digest_list->buf);
	kmem_cache_free(digest_list_item_cache, digest_list);
}

/**
 * digest_list_add - add a new digest list
 * @digest: digest of the digest list in binary form
 * @algo: digest algorithm
 * @size: digest list size
 * @buf: digest list buffer
 * @actions: actions (measure/appraise) performed by IMA on the digest list
 * @label: label to be used to identify the digest list
 *
 * This function allocates a new digest list item, which contains the buffer,
 * size, actions performed by IMA and a label. Each digest list item is
 * associated to a digest item representing the digest of the digest list.
 *
 * This function prevents the same digest list to be added multiple times by
 * searching its digest in the hash table for the COMPACT_DIGEST_LIST type.
 *
 * The passed buffer is copied in a new memory area, to avoid to reference
 * memory that could be freed by the caller.
 *
 * If allocation of a new digest list and the associated buffer was successful,
 * its digest is added to the hash table for the COMPACT_DIGEST_LIST type.
 *
 * Proper locking must be provided by the caller.
 *
 * Return: the digest item associated to the digest list item on success, an
 * error pointer otherwise.
 */
struct digest_item *digest_list_add(u8 *digest, enum hash_algo algo,
				    loff_t size, u8 *buf, u8 actions,
				    const char *label)
{
	struct digest_item *d;
	struct digest_list_item *digest_list = NULL;
	int digest_len = hash_digest_size[algo];

	/* Search the digest of the digest list. */
	d = __digest_lookup(digest, algo, COMPACT_DIGEST_LIST, NULL, NULL);
	if (d) {
		print_hex_dump_debug("digest list already uploaded: ",
				     DUMP_PREFIX_NONE, digest_len, 1, digest,
				     digest_len, true);
		return ERR_PTR(-EEXIST);
	}

	/* Allocate a new digest list. */
	if (!should_fail_diglim())
		digest_list = kmem_cache_alloc(digest_list_item_cache,
					       GFP_KERNEL);
	if (!digest_list) {
		print_hex_dump(KERN_ERR, "digest list allocation failed: ",
			       DUMP_PREFIX_NONE, digest_len, 1, digest,
			       digest_len, true);
		return ERR_PTR(-ENOMEM);
	}

	digest_list->buf = NULL;
	digest_list->size = size;
	digest_list->label = NULL;

	if (!should_fail_diglim())
		digest_list->buf = kmemdup(buf, size, GFP_KERNEL);
	if (!digest_list->buf) {
		print_hex_dump(KERN_ERR, "digest list allocation failed: ",
			       DUMP_PREFIX_NONE, digest_len, 1, digest,
			       digest_len, true);
		digest_list_free(digest_list);
		return ERR_PTR(-ENOMEM);
	}

	digest_list->actions = actions;
	memcpy(digest_list->digest, digest, hash_digest_size[algo]);
	digest_list->algo = algo;
	if (!should_fail_diglim())
		digest_list->label = kstrdup(label, GFP_KERNEL);
	if (!digest_list->label) {
		print_hex_dump(KERN_ERR, "digest list allocation failed: ",
			       DUMP_PREFIX_NONE, digest_len, 1, digest,
			       digest_len, true);
		digest_list_free(digest_list);
		return ERR_PTR(-ENOMEM);
	}

	/* Add the digest of the digest list to the hash table. */
	d = digest_add(digest, algo, COMPACT_DIGEST_LIST, digest_list, 0, 0);
	if (IS_ERR(d))
		digest_list_free(digest_list);

	return d;
}

/**
 * digest_list_del - delete an existing digest list
 * @digest: digest of the digest list in binary form
 * @algo: digest algorithm
 * @actions: actions (measure/appraise) performed by IMA on the digest list
 * @digest_list: digest list to delete
 *
 * This function searches the digest of the digest list in the hash table for
 * the COMPACT_DIGEST_LIST type. If it is found, this function frees the buffer
 * and the digest list item allocated in digest_list_add().
 *
 * This function will be executed only for digest lists that were previously
 * added.
 *
 * Proper locking must be provided by the caller.
 */
void digest_list_del(u8 *digest, enum hash_algo algo, u8 actions,
		     struct digest_list_item *digest_list)
{
	/* Delete the digest item associated to the digest list. */
	digest_del(digest, algo, COMPACT_DIGEST_LIST, digest_list, 0, 0);

	/*
	 * Free the buffer, the label and the digest list item allocated when
	 * the digest list was added.
	 */
	digest_list_free(digest_list);
}

static int __init digest_list_cache_init(void)
{
	digest_list_item_cache = kmem_cache_create("digest_list_item_cache",
						sizeof(struct digest_list_item),
						0, SLAB_PANIC, NULL);

	digest_list_item_ref_cache = kmem_cache_create(
					"digest_list_item_ref_cache",
					sizeof(struct digest_list_item_ref), 0,
					SLAB_PANIC, NULL);

	digest_item_cache = kmem_cache_create("digest_item_cache",
					      sizeof(struct digest_item), 0,
					      SLAB_PANIC, NULL);

	return 0;
}

late_initcall(digest_list_cache_init)
