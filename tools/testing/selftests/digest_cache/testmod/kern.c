// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the kernel module to interact with the digest_cache LSM.
 */

#define pr_fmt(fmt) "DIGEST CACHE TEST: "fmt
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/dynamic_debug.h>
#include <linux/digest_cache.h>
#include <linux/kprobes.h>
#include <linux/cpu.h>
#include <linux/kernel_read_file.h>
#include <crypto/hash_info.h>

#include "../common.h"

struct verif {
	int (*update)(struct file *file);
	ssize_t (*read)(struct file *file, char __user *buf, size_t datalen,
			loff_t *ppos);
	bool enabled;
};

struct read_work {
	struct work_struct work;
	char *path_str;
	int ret;
};

static struct dentry *test;
static struct digest_cache *digest_cache;
static digest_cache_found_t found;
static int cur_verif_index;
static u8 prefetch_buf[4096];
static struct read_work w[MAX_WORKS];

static int filenames_update(struct file *file)
{
	char *filename = (char *)file->f_path.dentry->d_name.name;

	return digest_cache_verif_set(file, "filenames", filename,
				      strlen(filename) + 1);
}

static int number_update(struct file *file)
{
	const char *filename = file_dentry(file)->d_name.name;
	size_t filename_len = strlen(filename);
	u64 number = U64_MAX;
	int ret;

	while (filename_len) {
		if (filename[filename_len - 1] < '0' ||
		    filename[filename_len - 1] > '9')
			break;

		filename_len--;
	}

	ret = kstrtoull(filename + filename_len, 10, &number);
	if (ret < 0) {
		pr_debug("Failed to convert filename %s into number\n",
			 file_dentry(file)->d_name.name);
		return ret;
	}

	return digest_cache_verif_set(file, "number", &number, sizeof(number));
}

static ssize_t filenames_read(struct file *file, char __user *buf,
			      size_t datalen, loff_t *ppos)
{
	loff_t _ppos = 0;
	char *filenames_list;

	filenames_list = digest_cache_verif_get(found ?
				digest_cache_from_found_t(found) : digest_cache,
				verifs_str[VERIF_FILENAMES]);
	if (!filenames_list)
		return -ENOENT;

	return simple_read_from_buffer(buf, datalen, &_ppos, filenames_list,
				       strlen(filenames_list) + 1);
}

static ssize_t number_read(struct file *file, char __user *buf, size_t datalen,
			   loff_t *ppos)
{
	loff_t _ppos = 0;
	u64 *number;
	char temp[20];
	ssize_t len;

	number = digest_cache_verif_get(found ?
					digest_cache_from_found_t(found) :
					digest_cache, verifs_str[VERIF_NUMBER]);
	if (!number)
		return -ENOENT;

	len = snprintf(temp, sizeof(temp), "%llu", *number);

	return simple_read_from_buffer(buf, datalen, &_ppos, temp, len);
}

static int prefetch_update(struct file *file)
{
	char *filename = (char *)file->f_path.dentry->d_name.name;
	char *start_ptr = prefetch_buf, *end_ptr;
	int ret;

	ret = digest_cache_verif_set(file, "probe_digest_cache", "1", 1);
	if (!ret) {
		/* Don't include duplicates of requested digest lists. */
		while ((end_ptr = strchrnul(start_ptr, ','))) {
			if (end_ptr > start_ptr &&
			    !strncmp(start_ptr, filename, end_ptr - start_ptr))
				return 0;

			if (!*end_ptr)
				break;

			start_ptr = end_ptr + 1;
		}
	}

	if (prefetch_buf[0])
		strlcat(prefetch_buf, ",", sizeof(prefetch_buf));

	strlcat(prefetch_buf, filename, sizeof(prefetch_buf));
	return 0;
}

static ssize_t prefetch_read(struct file *file, char __user *buf,
			     size_t datalen, loff_t *ppos)
{
	loff_t _ppos = 0;

	return simple_read_from_buffer(buf, datalen, &_ppos, prefetch_buf,
				       strlen(prefetch_buf) + 1);
}

static struct verif verifs_methods[] = {
	[VERIF_FILENAMES] = { .update = filenames_update,
			      .read = filenames_read },
	[VERIF_NUMBER] = { .update = number_update, .read = number_read },
	[VERIF_PREFETCH] = { .update = prefetch_update, .read = prefetch_read },
};

static void digest_cache_get_put_work(struct work_struct *work)
{
	struct read_work *w = container_of(work, struct read_work, work);
	struct digest_cache *digest_cache;
	struct path path;

	w->ret = kern_path(w->path_str, 0, &path);
	if (w->ret < 0)
		return;

	digest_cache = digest_cache_get(path.dentry);

	path_put(&path);

	if (!digest_cache) {
		w->ret = -ENOENT;
		return;
	}

	digest_cache_put(digest_cache);
	w->ret = 0;
}

static int digest_cache_get_put_async(char *path_str, int start_number,
				      int end_number)
{
	int ret = 0, i;

	cpus_read_lock();
	for (i = start_number; i <= end_number; i++) {
		w[i].path_str = kasprintf(GFP_KERNEL, "%s%u", path_str, i);
		if (!w[i].path_str) {
			ret = -ENOMEM;
			break;
		}

		INIT_WORK_ONSTACK(&w[i].work, digest_cache_get_put_work);
		schedule_work_on(i % num_online_cpus(), &w[i].work);
	}
	cpus_read_unlock();

	for (i = start_number; i <= end_number; i++) {
		if (!w[i].path_str)
			continue;

		flush_work(&w[i].work);
		destroy_work_on_stack(&w[i].work);
		kfree(w[i].path_str);
		w[i].path_str = NULL;
		if (!ret)
			ret = w[i].ret;
	}

	return ret;
}

static ssize_t write_request(struct file *file, const char __user *buf,
			     size_t datalen, loff_t *ppos)
{
	char *data, *data_ptr, *cmd_str, *path_str, *algo_str, *digest_str;
	char *verif_name_str, *start_number_str, *end_number_str;
	u8 digest[64];
	struct path path;
	int ret, cmd, algo, verif_index, start_number, end_number;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data))
		return PTR_ERR(data);

	data_ptr = data;

	cmd_str = strsep(&data_ptr, "|");
	if (!cmd_str) {
		pr_debug("No command\n");
		ret = -EINVAL;
		goto out;
	}

	cmd = match_string(commands_str, DIGEST_CACHE__LAST, cmd_str);
	if (cmd < 0) {
		pr_err("Unknown command %s\n", cmd_str);
		ret = -ENOENT;
		goto out;
	}

	switch (cmd) {
	case DIGEST_CACHE_GET:
		found = 0UL;

		path_str = strsep(&data_ptr, "|");
		if (!path_str) {
			pr_debug("No path\n");
			ret = -EINVAL;
			goto out;
		}

		ret = kern_path(path_str, 0, &path);
		if (ret < 0) {
			pr_debug("Cannot find file %s\n", path_str);
			goto out;
		}

		if (digest_cache) {
			pr_debug("Digest cache exists, doing a put\n");
			digest_cache_put(digest_cache);
		}

		digest_cache = digest_cache_get(path.dentry);
		ret = digest_cache ? 0 : -ENOENT;
		pr_debug("digest cache get %s, ret: %d\n", path_str, ret);
		path_put(&path);
		break;
	case DIGEST_CACHE_LOOKUP:
		if (!digest_cache) {
			pr_debug("No digest cache\n");
			ret = -ENOENT;
			goto out;
		}

		path_str = strsep(&data_ptr, "|");
		if (!path_str) {
			pr_debug("No path\n");
			ret = -EINVAL;
			goto out;
		}

		algo_str = strsep(&data_ptr, ":");
		digest_str = data_ptr;

		if (!algo_str || !digest_str) {
			pr_debug("No algo or digest\n");
			ret = -EINVAL;
			goto out;
		}

		algo = match_string(hash_algo_name, HASH_ALGO__LAST, algo_str);
		if (algo < 0) {
			pr_err("Unknown algorithm %s", algo_str);
			ret = -ENOENT;
			goto out;
		}

		ret = hex2bin(digest, digest_str, hash_digest_size[algo]);
		if (ret < 0) {
			pr_debug("Invalid digest %s\n", digest_str);
			goto out;
		}

		ret = kern_path(path_str, 0, &path);
		if (ret < 0) {
			pr_debug("Cannot find file %s\n", path_str);
			goto out;
		}

		ret = -ENOENT;

		found = digest_cache_lookup(path.dentry, digest_cache, digest,
					    algo);
		path_put(&path);
		if (found)
			ret = 0;

		pr_debug("%s:%s lookup %s, ret: %d\n", algo_str, digest_str,
			 path_str, ret);
		break;
	case DIGEST_CACHE_PUT:
		if (digest_cache) {
			digest_cache_put(digest_cache);
			digest_cache = NULL;
		}
		ret = 0;
		pr_debug("digest cache put, ret: %d\n", ret);
		break;
	case DIGEST_CACHE_ENABLE_VERIF:
	case DIGEST_CACHE_DISABLE_VERIF:
		memset(prefetch_buf, 0, sizeof(prefetch_buf));
		fallthrough;
	case DIGEST_CACHE_SET_VERIF:
		verif_name_str = strsep(&data_ptr, "|");
		if (!verif_name_str) {
			pr_debug("No verifier name\n");
			ret = -EINVAL;
			goto out;
		}

		verif_index = match_string(verifs_str, ARRAY_SIZE(verifs_str),
					   verif_name_str);
		if (verif_index < 0) {
			pr_err("Unknown verifier name %s\n", verif_name_str);
			ret = -ENOENT;
			goto out;
		}

		if (cmd == DIGEST_CACHE_ENABLE_VERIF)
			verifs_methods[verif_index].enabled = true;
		else if (cmd == DIGEST_CACHE_DISABLE_VERIF)
			verifs_methods[verif_index].enabled = false;
		else
			cur_verif_index = verif_index;

		ret = 0;
		pr_debug("digest cache %s %s, ret: %d\n", cmd_str,
			 verif_name_str, ret);
		break;
	case DIGEST_CACHE_GET_PUT_ASYNC:
		path_str = strsep(&data_ptr, "|");
		if (!path_str) {
			pr_debug("No path\n");
			ret = -EINVAL;
			goto out;
		}

		start_number_str = strsep(&data_ptr, "|");
		if (!start_number_str) {
			pr_debug("No start number\n");
			ret = -EINVAL;
			goto out;
		}

		ret = kstrtoint(start_number_str, 10, &start_number);
		if (ret < 0) {
			pr_debug("Invalid start number %s\n", start_number_str);
			ret = -EINVAL;
			goto out;
		}

		end_number_str = strsep(&data_ptr, "|");
		if (!end_number_str) {
			pr_debug("No end number\n");
			ret = -EINVAL;
			goto out;
		}

		ret = kstrtoint(end_number_str, 10, &end_number);
		if (ret < 0) {
			pr_debug("Invalid end number %s\n", end_number_str);
			ret = -EINVAL;
			goto out;
		}

		if (end_number - start_number >= MAX_WORKS) {
			pr_debug("Too many works (%d), max %d\n",
				 end_number - start_number, MAX_WORKS - 1);
			ret = -EINVAL;
			goto out;
		}

		ret = digest_cache_get_put_async(path_str, start_number,
						 end_number);
		pr_debug("digest cache %s on %s, start: %d, end: %d, ret: %d\n",
			 cmd_str, path_str, start_number, end_number, ret);
		break;
	case DIGEST_CACHE_RESET_PREFETCH_BUF:
		memset(prefetch_buf, 0, sizeof(prefetch_buf));
		pr_debug("digest cache %s\n", cmd_str);
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}
out:
	kfree(data);
	return ret ?: datalen;
}

static ssize_t read_request(struct file *file, char __user *buf, size_t datalen,
			    loff_t *ppos)
{
	return verifs_methods[cur_verif_index].read(file, buf, datalen, ppos);
}

static const struct file_operations digest_cache_test_ops = {
	.open = generic_file_open,
	.write = write_request,
	.read = read_request,
	.llseek = generic_file_llseek,
};

static int __kprobes kernel_post_read_file_hook(struct kprobe *p,
						struct pt_regs *regs)
{
#ifdef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	enum kernel_read_file_id id = regs_get_kernel_argument(regs, 3);
#else
	struct file *file = NULL;
	enum kernel_read_file_id id = READING_UNKNOWN;
#endif
	int ret, i;

	if (id != READING_DIGEST_LIST)
		return 0;

	for (i = 0; i < ARRAY_SIZE(verifs_methods); i++) {
		if (!verifs_methods[i].enabled)
			continue;

		ret = verifs_methods[i].update(file);
		if (ret < 0)
			return 0;
	}

	return 0;
}

static struct kprobe kp = {
	.symbol_name = "security_kernel_post_read_file",
};

static int __init digest_cache_test_init(void)
{
	int ret;

	kp.pre_handler = kernel_post_read_file_hook;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}

	test = securityfs_create_file("digest_cache_test", 0660, NULL, NULL,
				      &digest_cache_test_ops);
	if (IS_ERR(test)) {
		unregister_kprobe(&kp);
		return PTR_ERR(test);
	}

	return 0;
}

static void __exit digest_cache_test_fini(void)
{
	if (digest_cache)
		digest_cache_put(digest_cache);

	securityfs_remove(test);
	unregister_kprobe(&kp);
	pr_debug("kprobe at %p unregistered\n", kp.addr);
}

module_init(digest_cache_test_init);
module_exit(digest_cache_test_fini);
MODULE_LICENSE("GPL");
