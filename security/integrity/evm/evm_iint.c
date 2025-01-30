// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2008 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * File: evm_iint.c
 *	- implements the EVM hooks: evm_inode_alloc_security evm_inode_free_rcu
 *	- cache integrity information in the inode security blob
 */
#include <linux/slab.h>

#include "evm.h"

static struct kmem_cache *evm_iint_cache __ro_after_init;

/**
 * evm_iint_find - Return the iint associated with an inode
 * @inode: Pointer to the inode
 *
 * Return the EVM integrity information (iint) associated with an inode, if the
 * inode was processed by EVM.
 *
 * Return: Found iint or NULL.
 */
struct evm_iint_cache *evm_iint_find(struct inode *inode)
{
	struct evm_iint_cache_lock *iint_lock;

	iint_lock = evm_inode_security(inode->i_security);
	if (!iint_lock)
		return NULL;

	return READ_ONCE(iint_lock->iint);
}

static void evm_iint_init_always(struct evm_iint_cache *iint,
				 struct inode *inode)
{
	iint->flags = 0UL;
	iint->evm_status = INTEGRITY_UNKNOWN;
	iint->metadata_inode.version = 0;
	iint->metadata_inode.ino = 0;
	iint->metadata_inode.dev = 0;
}

/**
 * evm_inode_get - Find or allocate an iint associated with an inode
 * @inode: Pointer to the inode
 *
 * Find an iint associated with an inode, and allocate a new one if not found.
 * Caller must lock evm_iint_lock mutex.
 *
 * Return: An iint on success, NULL on error.
 */
struct evm_iint_cache *evm_inode_get(struct inode *inode)
{
	struct evm_iint_cache_lock *iint_lock;
	struct evm_iint_cache *iint;

	iint_lock = evm_inode_security(inode->i_security);
	if (!iint_lock)
		return NULL;

	lockdep_assert_held(&iint_lock->mutex);

	iint = READ_ONCE(iint_lock->iint);
	if (iint)
		return iint;

	iint = kmem_cache_alloc(evm_iint_cache, GFP_NOFS);
	if (!iint)
		return NULL;

	evm_iint_init_always(iint, inode);

	WRITE_ONCE(iint_lock->iint, iint);

	return iint;
}

/**
 * evm_inode_alloc_security - Called to init an inode
 * @inode: Pointer to the inode
 *
 * Initialize the mutex in the evm_iint_cache_lock structure.
 *
 * Return: Zero.
 */
int evm_inode_alloc_security(struct inode *inode)
{
	struct evm_iint_cache_lock *iint_lock;

	iint_lock = evm_inode_security(inode->i_security);

	mutex_init(&iint_lock->mutex);

	return 0;
}

/**
 * evm_inode_free_rcu - Called to free an inode via a RCU callback
 * @inode_security: The inode->i_security pointer
 *
 * Free the EVM data associated with an inode.
 */
void evm_inode_free_rcu(void *inode_security)
{
	struct evm_iint_cache_lock *iint_lock;

	iint_lock = evm_inode_security(inode_security);

	mutex_destroy(&iint_lock->mutex);

	if (iint_lock->iint)
		kmem_cache_free(evm_iint_cache, iint_lock->iint);
}

/**
 * evm_iint_lock - Lock integrity metadata
 * @inode: Pointer to the inode
 *
 * Lock integrity metadata.
 */
void evm_iint_lock(struct inode *inode)
{
	struct evm_iint_cache_lock *iint_lock;

	iint_lock = evm_inode_security(inode->i_security);

	/* Only inodes with i_security are processed by EVM. */
	if (iint_lock)
		mutex_lock(&iint_lock->mutex);
}

/**
 * evm_iint_unlock - Unlock integrity metadata
 * @inode: Pointer to the inode
 *
 * Unlock integrity metadata.
 */
void evm_iint_unlock(struct inode *inode)
{
	struct evm_iint_cache_lock *iint_lock;

	iint_lock = evm_inode_security(inode->i_security);

	/* Only inodes with i_security are processed by EVM. */
	if (iint_lock)
		mutex_unlock(&iint_lock->mutex);
}

static void evm_iint_init_once(void *foo)
{
	struct evm_iint_cache *iint = (struct evm_iint_cache *)foo;

	memset(iint, 0, sizeof(*iint));
}

void __init evm_iintcache_init(void)
{
	evm_iint_cache =
	    kmem_cache_create("evm_iint_cache", sizeof(struct evm_iint_cache),
			      0, SLAB_PANIC, evm_iint_init_once);
}
