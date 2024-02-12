// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the main code of the digest_cache LSM.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include <linux/namei.h>
#include <linux/xattr.h>

#include "internal.h"

static int digest_cache_enabled __ro_after_init = 1;
static struct kmem_cache *digest_cache_cache __read_mostly;

char *default_path_str = CONFIG_DIGEST_LIST_DEFAULT_PATH;

/* Protects default_path_str. */
struct rw_semaphore default_path_sem;

/**
 * digest_cache_alloc_init - Allocate and initialize a new digest cache
 * @path_str: Path string of the digest list
 * @filename: Digest list file name (can be an empty string)
 *
 * This function allocates and initializes a new digest cache.
 *
 * Return: A digest_cache structure on success, NULL on error.
 */
static struct digest_cache *digest_cache_alloc_init(char *path_str,
						    char *filename)
{
	struct digest_cache *digest_cache;

	digest_cache = kmem_cache_alloc(digest_cache_cache, GFP_KERNEL);
	if (!digest_cache)
		return digest_cache;

	digest_cache->path_str = kasprintf(GFP_KERNEL, "%s%s%s", path_str,
					   filename[0] ? "/" : "", filename);
	if (!digest_cache->path_str) {
		kmem_cache_free(digest_cache_cache, digest_cache);
		return NULL;
	}

	atomic_set(&digest_cache->ref_count, 1);
	digest_cache->flags = 0UL;
	INIT_LIST_HEAD(&digest_cache->htables);
	INIT_LIST_HEAD(&digest_cache->verif_data);
	spin_lock_init(&digest_cache->verif_data_lock);
	INIT_LIST_HEAD(&digest_cache->dir_entries);

	pr_debug("New digest cache %s (ref count: %d)\n",
		 digest_cache->path_str, atomic_read(&digest_cache->ref_count));

	return digest_cache;
}

/**
 * digest_cache_free - Free all memory occupied by the digest cache
 * @digest_cache: Digest cache
 *
 * This function frees the memory occupied by the digest cache.
 */
static void digest_cache_free(struct digest_cache *digest_cache)
{
	digest_cache_htable_free(digest_cache);
	digest_cache_verif_free(digest_cache);
	digest_cache_dir_free(digest_cache);

	pr_debug("Freed digest cache %s\n", digest_cache->path_str);
	kfree(digest_cache->path_str);
	kmem_cache_free(digest_cache_cache, digest_cache);
}

/**
 * digest_cache_create - Create a digest cache
 * @dentry: Dentry of the inode for which the digest cache will be used
 * @digest_list_path: Path structure of the digest list
 * @path_str: Path string of the digest list
 * @filename: Digest list file name (can be an empty string)
 * @prefetch_req: Whether prefetching has been requested
 * @prefetch: Whether prefetching of a digest list is being done
 *
 * This function first locates, from the passed path, the digest list inode
 * from which the digest cache will be created or retrieved (if it already
 * exists).
 *
 * If dig_owner is NULL in the inode security blob, this function creates a
 * new digest cache with reference count set to 1 (reference returned), sets
 * it to dig_owner and consequently increments again the digest cache reference
 * count.
 *
 * Otherwise, it simply increments the reference count of the existing
 * dig_owner, since that reference is returned to the caller.
 *
 * Incrementing the reference count twice before calling path_put() ensures
 * that the digest cache returned is valid even if the inode is evicted from
 * memory (which decreases the reference count).
 *
 * Releasing the dig_owner_mutex lock does not mean that the digest cache is
 * ready for use. digest_cache_create() callers that found a partially
 * instantiated digest cache have to wait until the INIT_IN_PROGRESS bit is
 * cleared by the caller that is actually creating that digest cache.
 *
 * Return: A new digest cache on success, NULL on error.
 */
struct digest_cache *digest_cache_create(struct dentry *dentry,
					 struct path *digest_list_path,
					 char *path_str, char *filename,
					 bool prefetch_req, bool prefetch)
{
	struct path file_path;
	struct digest_cache *digest_cache = NULL;
	struct digest_cache_security *dig_sec;
	struct inode *inode = d_backing_inode(digest_list_path->dentry);
	bool dig_owner_exists = false;
	int ret;

	if (S_ISDIR(d_backing_inode(digest_list_path->dentry)->i_mode) &&
	    filename[0]) {
		ret = vfs_path_lookup(digest_list_path->dentry,
				      digest_list_path->mnt, filename, 0,
				      &file_path);
		if (ret < 0) {
			pr_debug("Cannot find digest list %s/%s\n", path_str,
				 filename);
			return NULL;
		}

		digest_list_path = &file_path;
		inode = d_backing_inode(file_path.dentry);

		/*
		 * Cannot request a digest cache for the same inode the
		 * digest cache is populated from.
		 */
		if (d_backing_inode(dentry) == inode) {
			pr_debug("Cannot request a digest cache for %s and use it as digest list\n",
				 dentry->d_name.name);
			goto out;
		}

		/* No support for nested directories. */
		if (!S_ISREG(inode->i_mode)) {
			pr_debug("%s is not a regular file (no support for nested directories)\n",
				 dentry->d_name.name);
			goto out;
		}

		if (prefetch) {
			/* Fine to fail, we are just prefetching. */
			ret = digest_cache_populate(NULL, digest_list_path,
						    path_str, filename);
			pr_debug("Digest list %s/%s %s prefetched\n",
				 path_str, filename,
				 !ret ? "has been" : "cannot be");
			goto out;
		}
	}

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		goto out;

	/* Serialize check and assignment of dig_owner. */
	mutex_lock(&dig_sec->dig_owner_mutex);
	if (dig_sec->dig_owner) {
		/* Increment ref. count for reference returned to the caller. */
		digest_cache = digest_cache_ref(dig_sec->dig_owner);
		dig_owner_exists = true;
		mutex_unlock(&dig_sec->dig_owner_mutex);
		goto exists;
	}

	/* Ref. count is already 1 for this reference. */
	digest_cache = digest_cache_alloc_init(path_str, filename);
	if (!digest_cache) {
		mutex_unlock(&dig_sec->dig_owner_mutex);
		goto out;
	}

	/* Increment ref. count for reference set to dig_owner. */
	dig_sec->dig_owner = digest_cache_ref(digest_cache);

	/* Make the other lock contenders wait until creation complete. */
	set_bit(INIT_IN_PROGRESS, &dig_sec->dig_owner->flags);

	/* Set DIR_PREFETCH if prefetching was requested. */
	if (prefetch_req)
		set_bit(DIR_PREFETCH, &digest_cache->flags);

	mutex_unlock(&dig_sec->dig_owner_mutex);

	if (S_ISREG(inode->i_mode)) {
		ret = digest_cache_populate(digest_cache, digest_list_path,
					    path_str, filename);
		if (ret < 0) {
			pr_debug("Failed to populate digest cache %s ret: %d (keep digest cache)\n",
				 digest_cache->path_str, ret);
			/* Prevent usage of partially-populated digest cache. */
			set_bit(INVALID, &digest_cache->flags);
		}
	} else if (S_ISDIR(inode->i_mode)) {
		set_bit(IS_DIR, &dig_sec->dig_owner->flags);

		ret = digest_cache_dir_create(digest_cache, digest_list_path);
		if (ret < 0) {
			pr_debug("Failed to create dir digest cache, ret: %d (keep digest cache)\n",
				 ret);
			/* Prevent usage of partially-populated digest cache. */
			set_bit(INVALID, &dig_sec->dig_owner->flags);
		}
	}

	/* Creation complete, notify the other lock contenders. */
	clear_and_wake_up_bit(INIT_IN_PROGRESS, &dig_sec->dig_owner->flags);
exists:
	if (dig_owner_exists)
		/* Wait until creation complete. */
		wait_on_bit(&dig_sec->dig_owner->flags, INIT_IN_PROGRESS,
			    TASK_UNINTERRUPTIBLE);

	if (test_bit(INVALID, &digest_cache->flags)) {
		pr_debug("Digest cache %s is invalid, don't return it\n",
			 digest_cache->path_str);
		digest_cache_put(digest_cache);
		digest_cache = NULL;
	}
out:
	if (digest_list_path == &file_path)
		path_put(&file_path);

	return digest_cache;
}

/**
 * digest_cache_prefetch_requested - Verify if prefetching is requested
 * @digest_list_path: Path structure of the digest list directory
 * @path_str: Path string of the digest list directory
 *
 * This function verifies whether or not digest list prefetching is requested.
 * If dig_owner exists in the inode security blob, it checks the DIR_PREFETCH
 * bit (faster). Otherwise, it reads the new security.dig_prefetch xattr.
 *
 * Return: True if prefetching is requested, false otherwise.
 */
static bool digest_cache_prefetch_requested(struct path *digest_list_path,
					    char *path_str)
{
	struct digest_cache_security *dig_sec;
	bool prefetch_req = false;
	char prefetch_value;
	struct inode *inode;
	int ret;

	inode = d_backing_inode(digest_list_path->dentry);
	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		return false;

	mutex_lock(&dig_sec->dig_owner_mutex);
	if (dig_sec->dig_owner) {
		/* Reliable test: DIR_PREFETCH set with dig_owner_mutex held. */
		prefetch_req = test_bit(DIR_PREFETCH,
					&dig_sec->dig_owner->flags);
		mutex_unlock(&dig_sec->dig_owner_mutex);
		return prefetch_req;
	}
	mutex_unlock(&dig_sec->dig_owner_mutex);

	ret = vfs_getxattr(&nop_mnt_idmap, digest_list_path->dentry,
			   XATTR_NAME_DIG_PREFETCH, &prefetch_value, 1);
	if (ret == 1 && prefetch_value == '1') {
		pr_debug("Prefetching has been enabled for directory %s\n",
			 path_str);
		prefetch_req = true;
	}

	return prefetch_req;
}

/**
 * digest_cache_new - Retrieve digest list file name and request digest cache
 * @dentry: Dentry of the inode for which the digest cache will be used
 *
 * This function locates the default path. If it is a file, it directly creates
 * a digest cache from it. Otherwise, it reads the digest list file name from
 * the security.digest_list xattr and requests the creation of a digest cache
 * with that file name. If security.digest_list is not found, this function
 * requests the creation of a digest cache on the parent directory.
 *
 * On prefetching, if the default path is a directory and if
 * security.digest_list is found, this function first retrieves the directory
 * digest cache, and then calls digest_cache_dir_lookup_filename() to retrieve
 * the desired digest cache in that directory.
 *
 * Return: A new digest cache on success, NULL on error.
 */
static struct digest_cache *digest_cache_new(struct dentry *dentry)
{
	char filename[NAME_MAX + 1] = { 0 };
	struct digest_cache *digest_cache = NULL, *found;
	struct path default_path;
	bool prefetch_req = false;
	int ret;

	ret = kern_path(default_path_str, 0, &default_path);
	if (ret < 0) {
		pr_debug("Cannot find path %s\n", default_path_str);
		return NULL;
	}

	/* The default path is a file, no need to get xattr. */
	if (S_ISREG(d_backing_inode(default_path.dentry)->i_mode)) {
		pr_debug("Default path %s is a file, not reading %s xattr\n",
			 default_path_str, XATTR_NAME_DIGEST_LIST);
		goto create;
	} else if (!S_ISDIR(d_backing_inode(default_path.dentry)->i_mode)) {
		pr_debug("Default path %s must be either a file or a directory\n",
			 default_path_str);
		goto out;
	}

	ret = vfs_getxattr(&nop_mnt_idmap, dentry, XATTR_NAME_DIGEST_LIST,
			   filename, sizeof(filename) - 1);
	if (ret <= 0) {
		pr_debug("Digest list path not found for file %s, using %s\n",
			 dentry->d_name.name, default_path_str);
		goto create;
	}

	if (strchr(filename, '/')) {
		pr_debug("%s xattr should contain only a file name, got: %s\n",
			 XATTR_NAME_DIGEST_LIST, filename);
		goto out;
	}

	pr_debug("Found %s xattr in %s, default path: %s, digest list: %s\n",
		 XATTR_NAME_DIGEST_LIST, dentry->d_name.name, default_path_str,
		 filename);

	/* On prefetching, retrieve the directory digest cache. */
	if (filename[0])
		prefetch_req = digest_cache_prefetch_requested(&default_path,
							default_path_str);
create:
	digest_cache = digest_cache_create(dentry, &default_path,
					   default_path_str,
					   !prefetch_req ? filename : "",
					   prefetch_req, false);
	if (!digest_cache)
		goto out;

	if (prefetch_req) {
		/* Find the digest cache with a matching file name. */
		found = digest_cache_dir_lookup_filename(dentry, &default_path,
							 digest_cache,
							 filename);
		digest_cache_put(digest_cache);
		digest_cache = found;
	}
out:
	path_put(&default_path);
	return digest_cache;
}

/**
 * digest_cache_get - Get a digest cache for a given inode
 * @dentry: Dentry of the inode for which the digest cache will be used
 *
 * This function tries to find a digest cache from the inode security blob of
 * the passed dentry (dig_user field). If a digest cache was not found, it calls
 * digest_cache_new() to create a new one. In both cases, it increments the
 * digest cache reference count before returning the reference to the caller.
 *
 * The caller is responsible to call digest_cache_put() to release the digest
 * cache reference returned.
 *
 * Lock dig_user_mutex to protect against concurrent requests to obtain a digest
 * cache for the same inode, and to make other contenders wait until the first
 * requester finishes the process.
 *
 * Return: A digest cache on success, NULL otherwise.
 */
struct digest_cache *digest_cache_get(struct dentry *dentry)
{
	struct digest_cache_security *dig_sec;
	struct digest_cache *digest_cache = NULL;

	if (!digest_cache_enabled)
		return NULL;

	dig_sec = digest_cache_get_security(d_backing_inode(dentry));
	if (unlikely(!dig_sec))
		return NULL;

	/* Serialize accesses to inode for which the digest cache is used. */
	mutex_lock(&dig_sec->dig_user_mutex);
	if (!dig_sec->dig_user) {
		down_read(&default_path_sem);
		/* Consume extra reference from digest_cache_create(). */
		dig_sec->dig_user = digest_cache_new(dentry);
		up_read(&default_path_sem);
	}

	if (dig_sec->dig_user)
		/* Increment ref. count for reference returned to the caller. */
		digest_cache = digest_cache_ref(dig_sec->dig_user);

	mutex_unlock(&dig_sec->dig_user_mutex);
	return digest_cache;
}
EXPORT_SYMBOL_GPL(digest_cache_get);

/**
 * digest_cache_put - Release a digest cache reference
 * @digest_cache: Digest cache
 *
 * This function decrements the reference count of the digest cache passed as
 * argument. If the reference count reaches zero, it calls digest_cache_free()
 * to free the digest cache.
 */
void digest_cache_put(struct digest_cache *digest_cache)
{
	struct digest_cache *to_free;

	to_free = digest_cache_unref(digest_cache);
	if (!to_free)
		return;

	digest_cache_free(to_free);
}
EXPORT_SYMBOL_GPL(digest_cache_put);

struct lsm_blob_sizes digest_cache_blob_sizes __ro_after_init = {
	.lbs_inode = sizeof(struct digest_cache_security),
	.lbs_file = sizeof(struct digest_cache *),
};

/**
 * digest_cache_inode_alloc_security - Initialize inode security blob
 * @inode: Inode for which the security blob is initialized
 *
 * This function initializes the digest_cache_security structure, directly
 * stored in the inode security blob.
 *
 * Return: Zero.
 */
static int digest_cache_inode_alloc_security(struct inode *inode)
{
	struct digest_cache_security *dig_sec;

	/* The inode security blob is always allocated here. */
	dig_sec = digest_cache_get_security(inode);
	mutex_init(&dig_sec->dig_owner_mutex);
	mutex_init(&dig_sec->dig_user_mutex);
	return 0;
}

/**
 * digest_cache_inode_free_security - Release the digest cache references
 * @inode: Inode for which the digest cache references are released
 *
 * Since the inode is being evicted, this function releases the non-needed
 * references to the digest_caches stored in the digest_cache_security
 * structure.
 */
static void digest_cache_inode_free_security(struct inode *inode)
{
	struct digest_cache_security *dig_sec;

	dig_sec = digest_cache_get_security(inode);
	if (!dig_sec)
		return;

	mutex_destroy(&dig_sec->dig_owner_mutex);
	mutex_destroy(&dig_sec->dig_user_mutex);
	if (dig_sec->dig_owner)
		digest_cache_put(dig_sec->dig_owner);
	if (dig_sec->dig_user)
		digest_cache_put(dig_sec->dig_user);
}

static struct security_hook_list digest_cache_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_alloc_security, digest_cache_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, digest_cache_inode_free_security),
};

/**
 * digest_cache_init_once - Initialize the digest cache structure
 * @foo: Digest cache structure to initialize
 *
 * This function fills the digest cache structure with zeros.
 */
static void digest_cache_init_once(void *foo)
{
	struct digest_cache *digest_cache = (struct digest_cache *)foo;

	memset(digest_cache, 0, sizeof(*digest_cache));
}

static const struct lsm_id digest_cache_lsmid = {
	.name = "digest_cache",
	.id = LSM_ID_DIGEST_CACHE,
};

/**
 * digest_cache_init - Initialize the digest_cache LSM
 *
 * Initialize the digest_cache LSM, by instantiating a cache for the
 * digest_cache structure and by registering the digest_cache LSM hooks.
 */
static int __init digest_cache_init(void)
{
	init_rwsem(&default_path_sem);

	digest_cache_cache = kmem_cache_create("digest_cache_cache",
					       sizeof(struct digest_cache),
					       0, SLAB_PANIC,
					       digest_cache_init_once);

	security_add_hooks(digest_cache_hooks, ARRAY_SIZE(digest_cache_hooks),
			   &digest_cache_lsmid);
	return 0;
}

DEFINE_LSM(digest_cache) = {
	.name = "digest_cache",
	.enabled = &digest_cache_enabled,
	.init = digest_cache_init,
	.blobs = &digest_cache_blob_sizes,
};
