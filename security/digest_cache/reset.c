// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Reset/clear digest cache on digest lists/directory modifications.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include "internal.h"

/**
 * digest_cache_changed - Report whether or not the digest cache changed
 * @inode: Inode the digest cache was requested for
 * @digest_cache: Digest cache
 *
 * This function reports whether or not the digest cache changed since the
 * digest_cache_get() call to acquire the digest cache reference passed as
 * argument.
 *
 * Return: True if the digest cache changed, false otherwise.
 */
bool digest_cache_changed(struct inode *inode,
			  struct digest_cache *digest_cache)
{
	struct digest_cache_security *dig_sec;
	bool changed = false;

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		return false;

	mutex_lock(&dig_sec->dig_user_mutex);
	if (!dig_sec->dig_user || test_bit(RESET, &dig_sec->dig_user->flags))
		changed = true;
	mutex_unlock(&dig_sec->dig_user_mutex);
	return changed;
}
EXPORT_SYMBOL_GPL(digest_cache_changed);

/**
 * digest_cache_reset_owner - Reset dig_owner
 * @inode: Inode of the digest list/directory containing the digest list
 * @reason: Reason for reset
 *
 * This function sets the RESET bit of the digest cache pointed to by dig_owner,
 * so that digest_cache_get() and digest_cache_create() respectively release and
 * clear dig_user and dig_owner in the inode security blob. This causes new
 * callers of digest_cache_get() to get a new digest cache.
 */
static void digest_cache_reset_owner(struct inode *inode, const char *reason)
{
	struct digest_cache_security *dig_sec;

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		return;

	mutex_lock(&dig_sec->dig_owner_mutex);
	if (dig_sec->dig_owner) {
		pr_debug("Resetting %s (dig_owner), reason: %s\n",
			 dig_sec->dig_owner->path_str, reason);
		set_bit(RESET, &dig_sec->dig_owner->flags);
	}
	mutex_unlock(&dig_sec->dig_owner_mutex);
}

/**
 * digest_cache_clear_user - Clear dig_user
 * @inode: Inode of the file using the digest cache
 * @reason: Reason for reset
 *
 * This function releases the digest cache reference stored in dig_user of the
 * inode security blob and clears dig_user, so that new callers of
 * digest_cache_get() get a new digest cache.
 */
static void digest_cache_clear_user(struct inode *inode, const char *reason)
{
	struct digest_cache_security *dig_sec;

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		return;

	mutex_lock(&dig_sec->dig_user_mutex);
	if (dig_sec->dig_user) {
		pr_debug("Clearing %s (dig_user), reason: %s\n",
			 dig_sec->dig_user->path_str, reason);
		digest_cache_put(dig_sec->dig_user);
		dig_sec->dig_user = NULL;
	}
	mutex_unlock(&dig_sec->dig_user_mutex);
}

/**
 * digest_cache_file_open - A file is being opened
 * @file: File descriptor
 *
 * This function is called when a file is opened. If the inode is a digest list
 * and is opened for write, it resets the inode dig_owner, to force rebuilding
 * the digest cache.
 *
 * Return: Zero.
 */
int digest_cache_file_open(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode) || !(file->f_mode & FMODE_WRITE))
		return 0;

	digest_cache_reset_owner(file_inode(file), "file_open_write");
	return 0;
}

/**
 * digest_cache_path_truncate - A file is being truncated
 * @path: File path
 *
 * This function is called when a file is being truncated. If the inode is a
 * digest list, it resets the inode dig_owner, to force rebuilding the digest
 * cache.
 *
 * Return: Zero.
 */
int digest_cache_path_truncate(const struct path *path)
{
	struct inode *inode = d_backing_inode(path->dentry);

	if (!S_ISREG(inode->i_mode))
		return 0;

	digest_cache_reset_owner(inode, "file_truncate");
	return 0;
}

/**
 * digest_cache_file_release - Last reference of a file desc is being released
 * @file: File descriptor
 *
 * This function is called when the last reference of a file descriptor is
 * being released. If the parent inode is the digest list directory, the inode
 * is a regular file and was opened for write, it resets the inode dig_owner,
 * to force rebuilding the digest cache.
 */
void digest_cache_file_release(struct file *file)
{
	struct inode *dir = d_backing_inode(file_dentry(file)->d_parent);

	if (!S_ISREG(file_inode(file)->i_mode) || !(file->f_mode & FMODE_WRITE))
		return;

	digest_cache_reset_owner(dir, "dir_file_release");
}

/**
 * digest_cache_inode_unlink - An inode is being removed
 * @dir: Inode of the affected directory
 * @dentry: Dentry of the inode being removed
 *
 * This function is called when an existing inode is being removed. If the
 * inode is a digest list, or the parent inode is the digest list directory and
 * the inode is a regular file, it resets the affected inode dig_owner, to force
 * rebuilding the digest cache.
 *
 * Return: Zero.
 */
int digest_cache_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);

	if (!S_ISREG(inode->i_mode))
		return 0;

	digest_cache_reset_owner(inode, "file_unlink");
	digest_cache_reset_owner(dir, "dir_unlink");
	return 0;
}

/**
 * digest_cache_inode_rename - An inode is being renamed
 * @old_dir: Inode of the directory containing the inode being renamed
 * @old_dentry: Dentry of the inode being renamed
 * @new_dir: Directory where the inode will be placed into
 * @new_dentry: Dentry of the inode after being renamed
 *
 * This function is called when an existing inode is being moved from a
 * directory to another (rename). If the inode is a digest list, or that inode
 * is moved from/to the digest list directory, it resets the affected inode
 * dig_owner, to force rebuilding the digest cache.
 *
 * Return: Zero.
 */
int digest_cache_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			      struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = d_backing_inode(old_dentry);

	if (!S_ISREG(old_inode->i_mode))
		return 0;

	digest_cache_reset_owner(old_inode, "file_rename");
	digest_cache_reset_owner(old_dir, "dir_rename_from");
	digest_cache_reset_owner(new_dir, "dir_rename_to");
	return 0;
}

/**
 * digest_cache_inode_post_setxattr() - An xattr was set
 * @dentry: file
 * @name: xattr name
 * @value: xattr value
 * @size: size of xattr value
 * @flags: flags
 *
 * This function is called after an xattr was set on an existing inode. If the
 * inode is a digest list, it resets the affected inode dig_user, to force
 * retrieving a fresh digest cache.
 */
void digest_cache_inode_post_setxattr(struct dentry *dentry, const char *name,
				      const void *value, size_t size, int flags)
{
	if (strcmp(name, XATTR_NAME_DIGEST_LIST))
		return;

	digest_cache_clear_user(d_backing_inode(dentry), "file_setxattr");
}

/**
 * digest_cache_inode_post_removexattr() - An xattr was removed
 * @dentry: file
 * @name: xattr name
 *
 * This function is called after an xattr was removed from an existing inode.
 * If the inode is a digest list, it resets the affected inode dig_user, to
 * force retrieving a fresh digest cache.
 */
void digest_cache_inode_post_removexattr(struct dentry *dentry,
					 const char *name)
{
	if (strcmp(name, XATTR_NAME_DIGEST_LIST))
		return;

	digest_cache_clear_user(d_backing_inode(dentry), "file_removexattr");
}
