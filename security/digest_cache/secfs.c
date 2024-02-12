// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the securityfs interface of the digest_cache LSM.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include <linux/security.h>

#include "internal.h"

static struct dentry *default_path_dentry;

/**
 * write_default_path - Write default path
 * @file: File descriptor of the securityfs file
 * @buf: User space buffer
 * @datalen: Amount of data to write
 * @ppos: Current position in the file
 *
 * This function sets the new default path where digest lists can be found.
 * Can be either a regular file or a directory.
 *
 * Return: Length of path written on success, a POSIX error code otherwise.
 */
static ssize_t write_default_path(struct file *file, const char __user *buf,
				  size_t datalen, loff_t *ppos)
{
	char *new_default_path_str;

	new_default_path_str = memdup_user_nul(buf, datalen);
	if (IS_ERR(new_default_path_str))
		return PTR_ERR(new_default_path_str);

	down_write(&default_path_sem);
	kfree_const(default_path_str);
	default_path_str = new_default_path_str;
	up_write(&default_path_sem);
	return datalen;
}

/**
 * read_default_path - Read default path
 * @file: File descriptor of the securityfs file
 * @buf: User space buffer
 * @datalen: Amount of data to read
 * @ppos: Current position in the file
 *
 * This function returns the current default path where digest lists can be
 * found. Can be either a regular file or a directory.
 *
 * Return: Length of path read on success, a POSIX error code otherwise.
 */
static ssize_t read_default_path(struct file *file, char __user *buf,
				 size_t datalen, loff_t *ppos)
{
	int ret;

	down_read(&default_path_sem);
	ret = simple_read_from_buffer(buf, datalen, ppos, default_path_str,
				      strlen(default_path_str) + 1);
	up_read(&default_path_sem);
	return ret;
}

static const struct file_operations default_path_ops = {
	.open = generic_file_open,
	.write = write_default_path,
	.read = read_default_path,
	.llseek = generic_file_llseek,
};

static int __init digest_cache_path_init(void)
{
	default_path_dentry = securityfs_create_file("digest_cache_path", 0660,
						     NULL, NULL,
						     &default_path_ops);
	if (IS_ERR(default_path_dentry))
		return -EFAULT;

	return 0;
}

late_initcall(digest_cache_path_init);
