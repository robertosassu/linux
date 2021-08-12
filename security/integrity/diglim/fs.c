// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Functions for the interfaces exposed in securityfs.
 */

#include <linux/fcntl.h>
#include <linux/kernel_read_file.h>
#include <linux/module_signature.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>
#include <linux/vmalloc.h>
#include <linux/namei.h>
#include <linux/ima.h>

#include "diglim.h"

#define MAX_DIGEST_LIST_SIZE (64 * 1024 * 1024 - 1)

static struct dentry *diglim_dir;
/**
 * DOC: digest_list_add
 *
 * digest_list_add can be used to upload a digest list and add the digests
 * to the hash table; passed data are interpreted as file path if the first
 * byte is ``/`` or as the digest list itself otherwise.
 *
 * diglim_ima_get_info() is called to retrieve from IMA the digest of the passed
 * digest list (file or buffer), and the actions performed (measure/appraise/
 * appraise with signature).
 */
static struct dentry *digest_list_add_dentry;
/**
 * DOC: digest_list_del
 *
 * digest_list_del can be used to upload a digest list and delete the
 * digests from the hash table; data are interpreted in the same way as
 * described for digest_list_add.
 */
static struct dentry *digest_list_del_dentry;
char digest_list_label[NAME_MAX + 1];

/*
 * check_modsig: detect appended signature
 */
static int check_modsig(u8 *buf, size_t buf_len)
{
	const size_t marker_len = strlen(MODULE_SIG_STRING);
	const struct module_signature *sig;
	size_t sig_len;
	const void *p;

	if (buf_len <= marker_len + sizeof(*sig))
		return -ENOENT;

	p = buf + buf_len - marker_len;
	if (memcmp(p, MODULE_SIG_STRING, marker_len))
		return -ENOENT;

	sig = (const struct module_signature *)(p - sizeof(*sig));
	sig_len = be32_to_cpu(sig->sig_len);
	return marker_len + sig_len + sizeof(*sig);
}

/*
 * digest_list_read: read and parse the digest list from the path
 */
ssize_t digest_list_read(struct path *root, char *path, enum ops op)
{
	void *data = NULL;
	char *datap;
	size_t size;
	u8 actions = 0;
	struct file *file;
	char event_name[NAME_MAX + 9 + 1];
	u8 digest[IMA_MAX_DIGEST_SIZE] = { 0 };
	enum hash_algo algo;
	int rc, pathlen = strlen(path);

	/* Remove \n. */
	datap = path;
	strsep(&datap, "\n");

	if (root)
		file = file_open_root(root, path, O_RDONLY, 0);
	else
		file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file)) {
		pr_err("unable to open file: %s (%ld)", path, PTR_ERR(file));
		return PTR_ERR(file);
	}

	/* Deny writes to the file to obtain stable information from IMA. */
	rc = deny_write_access(file);
	if (rc < 0) {
		pr_err("unable to deny write access to file: %s (%d)", path,
			rc);
		goto out;
	}

	rc = kernel_read_file(file, 0, &data, INT_MAX, NULL,
			      READING_DIGEST_LIST);
	if (rc < 0) {
		pr_err("unable to read file: %s (%d)", path, rc);
		goto out_allow_write;
	}

	size = rc;
	rc = check_modsig(data, size);
	if (rc > 0)
		size -= rc;

	snprintf(event_name, sizeof(event_name), "%s_file_%s",
		 op == DIGEST_LIST_ADD ? "add" : "del",
		 file_dentry(file)->d_name.name);

	rc = diglim_ima_get_info(file, data, size, event_name, digest,
				 sizeof(digest), &algo, &actions);
	if (rc < 0) {
		pr_err("unable to retrieve IMA info for %s (%d)\n", path, rc);
		goto out_vfree;
	}

	rc = digest_list_parse(size, data, op, actions, digest, algo, "");
	if (rc < 0 && rc != -EEXIST)
		pr_err("unable to upload digest list %s (%d)\n", path, rc);
out_vfree:
	vfree(data);
out_allow_write:
	allow_write_access(file);
out:
	fput(file);

	if (rc < 0)
		return rc;

	return pathlen;
}

/*
 * digest_list_write: write the digest list path or the digest list itself
 */
static ssize_t digest_list_write(struct file *file, const char __user *buf,
				 size_t datalen, loff_t *ppos)
{
	char *data;
	char *digest_list_label_ptr;
	ssize_t result;
	enum ops op = DIGEST_LIST_ADD;
	struct dentry *dentry = file_dentry(file);
	u8 digest[IMA_MAX_DIGEST_SIZE];
	char event_name[NAME_MAX + 11 + 1];
	enum hash_algo algo;
	u8 actions = 0;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	result = -EFBIG;
	if (datalen > MAX_DIGEST_LIST_SIZE)
		goto out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		result = PTR_ERR(data);
		goto out;
	}

	if (dentry == digest_list_del_dentry)
		op = DIGEST_LIST_DEL;

	result = -EPERM;

	if (data[0] == '/') {
		result = digest_list_read(NULL, data, op);
	} else {
		/* Remove \n. */
		digest_list_label_ptr = digest_list_label;
		strsep(&digest_list_label_ptr, "\n");

		snprintf(event_name, sizeof(event_name), "%s_buffer_%s",
			 op == DIGEST_LIST_ADD ? "add" : "del",
			 digest_list_label);

		result = diglim_ima_get_info(NULL, data, datalen, event_name,
					     digest, sizeof(digest), &algo,
					     &actions);
		if (result < 0) {
			pr_err("unable to retrieve IMA info for buffer (%ld)\n",
			       result);
			goto out_kfree;
		}

		memset(digest_list_label, 0, sizeof(digest_list_label));

		result = digest_list_parse(datalen, data, op, actions, digest,
					   algo, "");
		if (result < 0 && result != -EEXIST)
			pr_err("unable to upload generated digest list\n");
	}
out_kfree:
	kfree(data);
out:
	return result;
}

static unsigned long flags;

/*
 * digest_list_open: sequentialize access to the add/del files
 */
static int digest_list_open(struct inode *inode, struct file *filp)
{
	if ((filp->f_flags & O_ACCMODE) != O_WRONLY)
		return -EACCES;

	if (test_and_set_bit(0, &flags))
		return -EBUSY;

	return 0;
}

/*
 * digest_list_release - release the add/del files
 */
static int digest_list_release(struct inode *inode, struct file *file)
{
	clear_bit(0, &flags);
	return 0;
}

static const struct file_operations digest_list_upload_ops = {
	.open = digest_list_open,
	.write = digest_list_write,
	.read = seq_read,
	.release = digest_list_release,
	.llseek = generic_file_llseek,
};

static int __init diglim_fs_init(void)
{
	diglim_dir = securityfs_create_dir("diglim", integrity_dir);
	if (IS_ERR(diglim_dir))
		return -1;

	digest_list_add_dentry = securityfs_create_file("digest_list_add", 0200,
						diglim_dir, NULL,
						&digest_list_upload_ops);
	if (IS_ERR(digest_list_add_dentry))
		goto out;

	digest_list_del_dentry = securityfs_create_file("digest_list_del", 0200,
						diglim_dir, NULL,
						&digest_list_upload_ops);
	if (IS_ERR(digest_list_del_dentry))
		goto out;

	return 0;
out:
	securityfs_remove(digest_list_del_dentry);
	securityfs_remove(digest_list_add_dentry);
	securityfs_remove(diglim_dir);
	return -1;
}

late_initcall(diglim_fs_init);
