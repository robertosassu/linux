/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Definitions only used inside DIGLIM.
 */

#ifndef __DIGLIM_INTERNAL_H
#define __DIGLIM_INTERNAL_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/tpm.h>
#include <linux/audit.h>
#include <crypto/hash_info.h>
#include <linux/hash_info.h>
#include <linux/diglim.h>

#include "../integrity.h"

#define MAX_DIGEST_SIZE 64
#define HASH_BITS 10
#define DIGLIM_HTABLE_SIZE (1 << HASH_BITS)

/**
 * struct digest_list_item - a digest list loaded into the kernel
 *
 * @size: size of the digest list buffer
 * @buf: digest list buffer
 * @digest: digest of the digest list
 * @label: label used to identify the digest list (e.g. file name)
 * @actions: actions performed on the digest list
 * @algo: digest algorithm
 */
struct digest_list_item {
	loff_t size;
	u8 *buf;
	u8 digest[64];
	const char *label;
	u8 actions;
	enum hash_algo algo;
};

/**
 * struct digest_list_item_ref - a reference to a digest list
 *
 * @list: linked list pointers
 * @digest_list: pointer to struct digest_list_item
 * @digest_offset: offset of the digest in the referenced digest list
 * @hdr_offset: offset of the header the digest refers to in the digest list
 */
struct digest_list_item_ref {
	struct list_head list;
	struct digest_list_item *digest_list;
	u32 digest_offset;
	u32 hdr_offset;
};

/**
 * struct digest_item - a digest of a digest list
 *
 * @hnext: pointers of the hash table
 * @refs: linked list of struct digest_list_item_ref
 */
struct digest_item {
	struct hlist_node hnext;
	struct list_head refs;
};

/**
 * struct h_table - hash table of struct digest_item
 *
 * @len: number of stored struct digest_item
 * @queue: heads of the hash table
 */
struct h_table {
	unsigned long len;
	struct hlist_head queue[DIGLIM_HTABLE_SIZE];
};

static inline unsigned int hash_key(u8 *digest)
{
	return (digest[0] | digest[1] << 8) % DIGLIM_HTABLE_SIZE;
}

extern struct h_table diglim_htable[COMPACT__LAST];

/**
 * get_hdr - get a compact header from a digest list
 * @digest_list: digest list the header is obtained from
 * @hdr_offset: header offset relative to the digest list buffer
 *
 * This function obtains a header from a digest list buffer and a header offset.
 *
 * Return: a compact list header
 */
static inline struct compact_list_hdr *
get_hdr(struct digest_list_item *digest_list, loff_t hdr_offset)
{
	return (struct compact_list_hdr *)(digest_list->buf + hdr_offset);
}

/**
 * get_algo - get a digest algorithm from a digest list
 * @digest_list: digest list the digest algorithm is obtained from
 * @digest_offset: offset of the digest relative to the digest list buffer
 * @hdr_offset: offset of the header relative to the digest list buffer
 *
 * This function returns the algorithm from struct digest_list_item if the
 * passed digest offset is zero, or from the header the digest refers to if the
 * digest offset is not zero.
 *
 * Return: the algorithm of the digest list digest or a digest inside the digest
 * list
 */
static inline enum hash_algo get_algo(struct digest_list_item *digest_list,
				      loff_t digest_offset, loff_t hdr_offset)
{
	/* Digest list digest algorithm is stored in a different place. */
	if (!digest_offset)
		return digest_list->algo;

	return get_hdr(digest_list, hdr_offset)->algo;
}

/**
 * get_digest - get a digest from a digest list
 * @digest_list: digest list the digest is obtained from
 * @digest_offset: offset of the digest relative to the digest list buffer
 * @hdr_offset: offset of the header relative to the digest list buffer
 *
 * This function returns the digest from struct digest_list_item if the
 * passed digest offset is zero, or from the digest list buffer if the
 * digest offset is not zero.
 *
 * Return: the digest list digest or a digest inside the digest list
 */
static inline u8 *get_digest(struct digest_list_item *digest_list,
			     loff_t digest_offset, loff_t hdr_offset)
{
	/* Digest list digest is stored in a different place. */
	if (!digest_offset)
		return digest_list->digest;

	return digest_list->buf + digest_offset;
}

/**
 * get_hdr_ref - get a compact header from a digest list reference
 * @ref: digest list reference the header is obtained from
 *
 * This function obtains a header from a digest list reference, which contains
 * the pointer to the digest list buffer and the digest and header offsets.
 *
 * Return: a compact list header
 */
static inline struct compact_list_hdr *
get_hdr_ref(struct digest_list_item_ref *ref)
{
	return get_hdr(ref->digest_list, ref->hdr_offset);
}

/**
 * get_algo_ref - get a digest algorithm from a digest list reference
 * @ref: digest list reference the digest algorithm is obtained from
 *
 * This function returns the algorithm from struct digest_list_item_ref, which
 * contains the pointer to the digest list buffer and the digest and header
 * offsets.
 *
 * Return: the algorithm of the digest list digest or a digest inside the digest
 * list
 */
static inline enum hash_algo get_algo_ref(struct digest_list_item_ref *ref)
{
	/* Digest list digest algorithm is stored in a different place. */
	if (!ref->digest_offset)
		return ref->digest_list->algo;

	return get_hdr_ref(ref)->algo;
}

/**
 * get_digest_ref - get a digest from a digest list reference
 * @ref: digest list reference the digest is obtained from
 *
 * This function returns the digest from struct digest_list_item_ref, which
 * contains the pointer to the digest list buffer and the digest and header
 * offsets.
 *
 * Return: the digest list digest or a digest inside the digest list
 */
static inline u8 *get_digest_ref(struct digest_list_item_ref *ref)
{
	/* Digest list digest is stored in a different place. */
	if (!ref->digest_offset)
		return ref->digest_list->digest;

	return ref->digest_list->buf + ref->digest_offset;
}

struct digest_item *__digest_lookup(u8 *digest, enum hash_algo algo,
				    enum compact_types type, u16 *modifiers,
				    u8 *actions);
struct digest_item *digest_add(u8 *digest, enum hash_algo algo,
			       enum compact_types type,
			       struct digest_list_item *digest_list,
			       loff_t digest_offset, loff_t hdr_offset);
void digest_del(u8 *digest, enum hash_algo algo, enum compact_types type,
		struct digest_list_item *digest_list, loff_t digest_offset,
		loff_t hdr_offset);
struct digest_item *digest_list_add(u8 *digest, enum hash_algo algo,
				    loff_t size, u8 *buf, u8 actions,
				    const char *label);
void digest_list_del(u8 *digest, enum hash_algo algo, u8 actions,
		     struct digest_list_item *digest_list);

int digest_list_parse(loff_t size, void *buf, enum ops op, u8 actions,
		      u8 *digest, enum hash_algo algo, const char *label);

int diglim_ima_get_info(struct file *file, u8 *buffer, size_t buffer_len,
			char *event_name, u8 *digest, size_t digest_len,
			enum hash_algo *algo, u8 *actions);

ssize_t digest_list_read(struct path *root, char *path, enum ops op);
#endif /*__DIGLIM_INTERNAL_H*/
