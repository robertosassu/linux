// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2008 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * File: ima_iint.c
 *	- implements the IMA hook: ima_inode_free
 *	- cache integrity information associated in the inode security blob
 */
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include "ima.h"

static struct kmem_cache *ima_iint_cache __ro_after_init;

/*
 * ima_iint_find - return the iint associated with an inode
 */
struct ima_iint_cache *ima_iint_find(struct inode *inode)
{
	if (!IS_IMA(inode))
		return NULL;

	return ima_inode_get_iint(inode);
}

#define IMA_MAX_NESTING (FILESYSTEM_MAX_STACK_DEPTH+1)

/*
 * It is not clear that IMA should be nested at all, but as long is it measures
 * files both on overlayfs and on underlying fs, we need to annotate the iint
 * mutex to avoid lockdep false positives related to IMA + overlayfs.
 * See ovl_lockdep_annotate_inode_mutex_key() for more details.
 */
static inline void ima_iint_lockdep_annotate(struct ima_iint_cache *iint,
					     struct inode *inode)
{
#ifdef CONFIG_LOCKDEP
	static struct lock_class_key ima_iint_mutex_key[IMA_MAX_NESTING];

	int depth = inode->i_sb->s_stack_depth;

	if (WARN_ON_ONCE(depth < 0 || depth >= IMA_MAX_NESTING))
		depth = 0;

	lockdep_set_class(&iint->mutex, &ima_iint_mutex_key[depth]);
#endif
}

static void ima_iint_init_always(struct ima_iint_cache *iint,
				 struct inode *inode)
{
	iint->ima_hash = NULL;
	iint->version = 0;
	iint->flags = 0UL;
	iint->atomic_flags = 0UL;
	iint->ima_file_status = INTEGRITY_UNKNOWN;
	iint->ima_mmap_status = INTEGRITY_UNKNOWN;
	iint->ima_bprm_status = INTEGRITY_UNKNOWN;
	iint->ima_read_status = INTEGRITY_UNKNOWN;
	iint->ima_creds_status = INTEGRITY_UNKNOWN;
	iint->measured_pcrs = 0;
	mutex_init(&iint->mutex);
	ima_iint_lockdep_annotate(iint, inode);
}

static void ima_iint_free(struct ima_iint_cache *iint)
{
	kfree(iint->ima_hash);
	mutex_destroy(&iint->mutex);
	kmem_cache_free(ima_iint_cache, iint);
}

/**
 * ima_inode_get - find or allocate an iint associated with an inode
 * @inode: pointer to the inode
 * @return: allocated iint
 *
 * Caller must lock i_mutex
 */
struct ima_iint_cache *ima_inode_get(struct inode *inode)
{
	struct ima_iint_cache *iint;

	iint = ima_iint_find(inode);
	if (iint)
		return iint;

	iint = kmem_cache_alloc(ima_iint_cache, GFP_NOFS);
	if (!iint)
		return NULL;

	ima_iint_init_always(iint, inode);

	inode->i_flags |= S_IMA;
	ima_inode_set_iint(inode, iint);

	return iint;
}

/**
 * ima_inode_free - called on inode free
 * @inode: pointer to the inode
 *
 * Free the IMA integrity information (iint) associated with an inode.
 */
void ima_inode_free(struct inode *inode)
{
	struct ima_iint_cache *iint;

	if (!IS_IMA(inode))
		return;

	iint = ima_iint_find(inode);
	ima_inode_set_iint(inode, NULL);

	ima_iint_free(iint);
}

static void ima_iint_init_once(void *foo)
{
	struct ima_iint_cache *iint = (struct ima_iint_cache *) foo;

	memset(iint, 0, sizeof(*iint));
}

void __init ima_iintcache_init(void)
{
	ima_iint_cache =
	    kmem_cache_create("ima_iint_cache", sizeof(struct ima_iint_cache),
			      0, SLAB_PANIC, ima_iint_init_once);
}
