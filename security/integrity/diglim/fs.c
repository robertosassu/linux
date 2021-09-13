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
 * DOC: digest_lists_loaded
 *
 * digest_lists_loaded is a directory containing two files for each
 * loaded digest list: one shows the digest list in binary format, and the
 * other (with .ascii prefix) shows the digest list in ASCII format.
 *
 * Files are added and removed at the same time digest lists are added and
 * removed.
 */
static struct dentry *digest_lists_loaded_dir;
/**
 * DOC: digest_list_label
 *
 * digest_list_label can be used to set a label to be applied to the next digest
 * list (buffer) loaded through digest_list_add.
 */
static struct dentry *digest_list_label_dentry;
/**
 * DOC: digest_query
 *
 * digest_query allows to write a query in the format <algo>-<digest> and
 * to obtain all digest lists that include that digest.
 */
static struct dentry *digest_query_dentry;
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
char digest_query[CRYPTO_MAX_ALG_NAME + 1 + IMA_MAX_DIGEST_SIZE * 2 + 1];
char digest_list_label[NAME_MAX + 1];

static int parse_digest_list_filename(const char *digest_list_filename,
				      u8 *digest, enum hash_algo *algo)
{
	u8 *sep;
	int i;

	sep = strchr(digest_list_filename, '-');
	if (!sep)
		return -EINVAL;

	*sep = '\0';
	i = match_string(hash_algo_name, HASH_ALGO__LAST, digest_list_filename);
	*sep = '-';

	if (i < 0)
		return -ENOENT;

	*algo = i;
	return hex2bin(digest, sep + 1, hash_digest_size[*algo]);
}

/* *pos is the offset of the digest list data to show. */
static void *digest_list_start(struct seq_file *m, loff_t *pos)
{
	struct digest_item *d;
	u8 digest[IMA_MAX_DIGEST_SIZE];
	enum hash_algo algo;
	struct digest_list_item *digest_list;
	int ret;

	if (m->private) {
		digest_list = (struct digest_list_item *)m->private;

		if (*pos == digest_list->size)
			return NULL;

		return digest_list->buf + *pos;
	}

	ret = parse_digest_list_filename(file_dentry(m->file)->d_name.name,
					 digest, &algo);
	if (ret < 0)
		return NULL;

	d = __digest_lookup(digest, algo, COMPACT_DIGEST_LIST, NULL, NULL);
	if (!d)
		return NULL;

	digest_list = list_first_entry(&d->refs,
				struct digest_list_item_ref, list)->digest_list;
	m->private = digest_list;
	return digest_list->buf;
}

static void *digest_list_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct compact_list_hdr *hdr;
	struct digest_list_item *digest_list =
					(struct digest_list_item *)m->private;
	void *bufp = digest_list->buf;
	bool is_header = false;

	/* Determine if v points to a header or a digest. */
	while (bufp <= v) {
		hdr = (struct compact_list_hdr *)bufp;
		if (bufp == v) {
			is_header = true;
			break;
		}

		bufp += sizeof(*hdr) + hdr->datalen;
	}

	if (is_header)
		*pos += sizeof(*hdr);
	else
		*pos += hash_digest_size[hdr->algo];

	if (*pos == digest_list->size)
		return NULL;

	return digest_list->buf + *pos;
}

static void digest_list_stop(struct seq_file *m, void *v)
{
}

static void print_digest(struct seq_file *m, u8 *digest, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++)
		seq_printf(m, "%02x", *(digest + i));
}

static void digest_list_putc(struct seq_file *m, void *data, int datalen)
{
	while (datalen--)
		seq_putc(m, *(char *)data++);
}

static int digest_list_show_common(struct seq_file *m, void *v, bool binary)
{
	struct compact_list_hdr *hdr, hdr_orig;
	struct digest_list_item *digest_list =
					(struct digest_list_item *)m->private;
	void *bufp = digest_list->buf;
	bool is_header = false;

	/* Determine if v points to a header or a digest. */
	while (bufp <= v) {
		hdr = (struct compact_list_hdr *)bufp;
		if (bufp == v) {
			is_header = true;
			break;
		}

		bufp += sizeof(*hdr) + hdr->datalen;
	}

	if (is_header) {
		if (binary) {
			memcpy(&hdr_orig, v, sizeof(hdr_orig));
			hdr_orig.type = cpu_to_le16(hdr_orig.type);
			hdr_orig.modifiers = cpu_to_le16(hdr_orig.modifiers);
			hdr_orig.algo = cpu_to_le16(hdr_orig.algo);
			hdr_orig.count = cpu_to_le32(hdr_orig.count);
			hdr_orig.datalen = cpu_to_le32(hdr_orig.datalen);
			digest_list_putc(m, &hdr_orig, sizeof(hdr_orig));
		} else {
			seq_printf(m,
				"actions: %d, version: %d, algo: %s, type: %d, modifiers: %d, count: %d, datalen: %d\n",
				digest_list->actions, hdr->version,
				hash_algo_name[hdr->algo], hdr->type,
				hdr->modifiers, hdr->count, hdr->datalen);
		}
		return 0;
	}

	if (binary) {
		digest_list_putc(m, v, hash_digest_size[hdr->algo]);
	} else {
		print_digest(m, v, hash_digest_size[hdr->algo]);
		seq_puts(m, "\n");
	}

	return 0;
}

static int digest_list_show(struct seq_file *m, void *v)
{
	return digest_list_show_common(m, v, true);
}

static int digest_list_ascii_show(struct seq_file *m, void *v)
{
	return digest_list_show_common(m, v, false);
}

static const struct seq_operations digest_list_seqops = {
	.start = digest_list_start,
	.next = digest_list_next,
	.stop = digest_list_stop,
	.show = digest_list_show
};

static int digest_list_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &digest_list_seqops);
}

static const struct file_operations digest_list_ops = {
	.open = digest_list_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static const struct seq_operations digest_list_ascii_seqops = {
	.start = digest_list_start,
	.next = digest_list_next,
	.stop = digest_list_stop,
	.show = digest_list_ascii_show
};

static int digest_list_ascii_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &digest_list_ascii_seqops);
}

static const struct file_operations digest_list_ascii_ops = {
	.open = digest_list_ascii_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/*
 * *pos is the n-th reference to show among all the references in all digest
 * items found with the query.
 */
static void *digest_query_start(struct seq_file *m, loff_t *pos)
{
	struct digest_item *d;
	u8 digest[IMA_MAX_DIGEST_SIZE];
	enum hash_algo algo;
	loff_t count = 0;
	enum compact_types type = 0;
	struct digest_list_item_ref *ref;
	int ret;

	ret = parse_digest_list_filename(digest_query, digest, &algo);
	if (ret < 0)
		return NULL;

	for (type = 0; type < COMPACT__LAST; type++) {
		d = __digest_lookup(digest, algo, type, NULL, NULL);
		if (!d)
			continue;

		list_for_each_entry(ref, &d->refs, list) {
			if (count++ == *pos) {
				m->private = d;
				return ref;
			}
		}
	}

	return NULL;
}

static void *digest_query_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct digest_item *d = (struct digest_item *)m->private;
	struct digest_list_item_ref *cur_ref = (struct digest_list_item_ref *)v;
	struct digest_list_item_ref *ref;

	(*pos)++;

	list_for_each_entry(ref, &d->refs, list) {
		if (ref != cur_ref)
			continue;

		if (!list_is_last(&cur_ref->list, &d->refs))
			return list_next_entry(cur_ref, list);
	}

	return NULL;
}

static void digest_query_stop(struct seq_file *m, void *v)
{
}

static int digest_query_show(struct seq_file *m, void *v)
{
	struct digest_list_item_ref *ref = (struct digest_list_item_ref *)v;
	struct digest_list_item *digest_list = ref->digest_list;
	struct compact_list_hdr *hdr = get_hdr_ref(ref);

	if (!ref->digest_offset) {
		seq_printf(m, "%s (actions: %d): type: %d, size: %lld\n",
			   digest_list->label, digest_list->actions,
			   COMPACT_DIGEST_LIST, digest_list->size);
		return 0;
	}

	seq_printf(m,
		"%s (actions: %d): version: %d, algo: %s, type: %d, modifiers: %d, count: %d, datalen: %d\n",
		digest_list->label, digest_list->actions, hdr->version,
		hash_algo_name[hdr->algo], hdr->type, hdr->modifiers,
		hdr->count, hdr->datalen);
	return 0;
}

static int digest_list_get_secfs_files(char *label, u8 *digest,
				       enum hash_algo algo, enum ops op,
				       struct dentry **dentry,
				       struct dentry **dentry_ascii)
{
	char digest_list_filename[NAME_MAX + 1] = { 0 };
	u8 digest_str[IMA_MAX_DIGEST_SIZE * 2 + 1] = { 0 };
	char *dot, *label_ptr;

	label_ptr = strrchr(label, '/');
	if (label_ptr)
		label = label_ptr + 1;

	bin2hex(digest_str, digest, hash_digest_size[algo]);

	snprintf(digest_list_filename, sizeof(digest_list_filename),
		 "%s-%s-%s.ascii", hash_algo_name[algo], digest_str, label);

	dot = strrchr(digest_list_filename, '.');

	*dot = '\0';
	if (op == DIGEST_LIST_ADD)
		*dentry = securityfs_create_file(digest_list_filename, 0440,
						 digest_lists_loaded_dir, NULL,
						 &digest_list_ops);
	else
		*dentry = lookup_positive_unlocked(digest_list_filename,
						digest_lists_loaded_dir,
						strlen(digest_list_filename));
	*dot = '.';
	if (IS_ERR(*dentry))
		return PTR_ERR(*dentry);

	if (op == DIGEST_LIST_ADD)
		*dentry_ascii = securityfs_create_file(digest_list_filename,
						0440, digest_lists_loaded_dir,
						NULL, &digest_list_ascii_ops);
	else
		*dentry_ascii = lookup_positive_unlocked(digest_list_filename,
						digest_lists_loaded_dir,
						strlen(digest_list_filename));
	if (IS_ERR(*dentry_ascii)) {
		if (op == DIGEST_LIST_ADD)
			securityfs_remove(*dentry);

		return PTR_ERR(*dentry_ascii);
	}

	return 0;
}

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
	struct dentry *dentry, *dentry_ascii;
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

	rc = digest_list_get_secfs_files(path, digest, algo, op, &dentry,
					 &dentry_ascii);
	if (rc < 0) {
		pr_err("unable to create securityfs entries for %s (%d)\n",
		       path, rc);
		goto out_vfree;
	}

	rc = digest_list_parse(size, data, op, actions, digest, algo,
			       dentry->d_name.name);
	if (rc < 0 && rc != -EEXIST)
		pr_err("unable to upload digest list %s (%d)\n", path, rc);

	/* Release reference taken in digest_list_get_secfs_files(). */
	if (op == DIGEST_LIST_DEL) {
		dput(dentry);
		dput(dentry_ascii);
	}

	if ((rc < 0 && rc != -EEXIST && op == DIGEST_LIST_ADD) ||
	    (rc == size && op == DIGEST_LIST_DEL)) {
		securityfs_remove(dentry);
		securityfs_remove(dentry_ascii);
	}
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
	struct dentry *dentry = file_dentry(file), *dentry_ascii;
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

		result = digest_list_get_secfs_files(
						digest_list_label[0] != '\0' ?
						digest_list_label : "parser",
						digest, algo, op, &dentry,
						&dentry_ascii);
		if (result < 0) {
			pr_err("unable to create securityfs entries for buffer (%ld)\n",
			       result);
			goto out_kfree;
		}

		memset(digest_list_label, 0, sizeof(digest_list_label));

		result = digest_list_parse(datalen, data, op, actions, digest,
					   algo, dentry->d_name.name);
		if (result < 0 && result != -EEXIST)
			pr_err("unable to upload generated digest list\n");

		/* Release reference taken in digest_list_get_secfs_files(). */
		if (op == DIGEST_LIST_DEL) {
			dput(dentry);
			dput(dentry_ascii);
		}

		if ((result < 0 && result != -EEXIST &&
		     op == DIGEST_LIST_ADD) ||
		    (result == datalen && op == DIGEST_LIST_DEL)) {
			securityfs_remove(dentry);
			securityfs_remove(dentry_ascii);
		}
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

/*
 * digest_list_label_write: write label for next uploaded digest list.
 */
static ssize_t digest_list_label_write(struct file *file,
				       const char __user *buf, size_t datalen,
				       loff_t *ppos)
{
	int rc, i;

	if (datalen >= sizeof(digest_list_label))
		return -EINVAL;

	rc = copy_from_user(digest_list_label, buf, datalen);
	if (rc)
		return -EFAULT;

	for (i = 0; i < datalen; i++) {
		if (!isgraph(digest_list_label[i]) &&
		    digest_list_label[i] != '\0') {
			memset(digest_list_label, 0, sizeof(digest_list_label));
			return -EINVAL;
		}
	}

	return datalen;
}

static const struct file_operations digest_list_label_ops = {
	.open = generic_file_open,
	.write = digest_list_label_write,
	.read = seq_read,
	.llseek = generic_file_llseek,
};

static const struct seq_operations digest_query_seqops = {
	.start = digest_query_start,
	.next = digest_query_next,
	.stop = digest_query_stop,
	.show = digest_query_show,
};

/*
 * digest_query_open: sequentialize access to the add/del/query files
 */
static int digest_query_open(struct inode *inode, struct file *file)
{
	if (test_and_set_bit(0, &flags))
		return -EBUSY;

	if (file->f_flags & O_WRONLY)
		return 0;

	return seq_open(file, &digest_query_seqops);
}

/*
 * digest_query_write: write digest query (<algo>-<digest>).
 */
static ssize_t digest_query_write(struct file *file, const char __user *buf,
				  size_t datalen, loff_t *ppos)
{
	char *sep;
	int rc, i;

	if (datalen >= sizeof(digest_query))
		return -EINVAL;

	rc = copy_from_user(digest_query, buf, datalen);
	if (rc)
		return -EFAULT;

	sep = strchr(digest_query, '-');
	if (!sep) {
		rc = -EINVAL;
		goto out;
	}

	*sep = '\0';
	i = match_string(hash_algo_name, HASH_ALGO__LAST, digest_query);
	if (i < 0) {
		rc = -ENOENT;
		goto out;
	}

	*sep = '-';

	for (i = 0; i < hash_digest_size[i] * 2; i++) {
		if (!isxdigit(sep[i + 1])) {
			rc = -EINVAL;
			goto out;
		}
	}
out:
	if (rc < 0) {
		memset(digest_query, 0, sizeof(digest_query));
		return rc;
	}

	return datalen;
}

/*
 * digest_query_release - release the query file
 */
static int digest_query_release(struct inode *inode, struct file *file)
{
	clear_bit(0, &flags);

	if (file->f_flags & O_WRONLY)
		return 0;

	return seq_release(inode, file);
}

static const struct file_operations digest_query_ops = {
	.open = digest_query_open,
	.write = digest_query_write,
	.read = seq_read,
	.release = digest_query_release,
	.llseek = generic_file_llseek,
};

static int __init diglim_fs_init(void)
{
	diglim_dir = securityfs_create_dir("diglim", integrity_dir);
	if (IS_ERR(diglim_dir))
		return -1;

	digest_lists_loaded_dir = securityfs_create_dir("digest_lists_loaded",
							diglim_dir);
	if (IS_ERR(digest_lists_loaded_dir))
		goto out;

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

	digest_list_label_dentry = securityfs_create_file("digest_list_label",
							0600, diglim_dir, NULL,
							&digest_list_label_ops);
	if (IS_ERR(digest_list_label_dentry))
		goto out;

	digest_query_dentry = securityfs_create_file("digest_query", 0600,
						     diglim_dir, NULL,
						     &digest_query_ops);
	if (IS_ERR(digest_query_dentry))
		goto out;

	return 0;
out:
	securityfs_remove(digest_query_dentry);
	securityfs_remove(digest_list_label_dentry);
	securityfs_remove(digest_list_del_dentry);
	securityfs_remove(digest_list_add_dentry);
	securityfs_remove(digest_lists_loaded_dir);
	securityfs_remove(diglim_dir);
	return -1;
}

late_initcall(diglim_fs_init);
