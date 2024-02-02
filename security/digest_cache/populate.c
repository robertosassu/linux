// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the code to populate a digest cache.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include <linux/init_task.h>
#include <linux/kernel_read_file.h>

#include "internal.h"
#include "parsers/parsers.h"

/**
 * digest_cache_parse_digest_list - Parse a digest list
 * @digest_cache: Digest cache
 * @path_str: Path string of the digest list
 * @filename: Digest list file name (can be an empty string)
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function selects a parser for a digest list depending on its file name,
 * and calls the appropriate parsing function. It expects the file name to be
 * in the format: [<seq num>-]<format>-<digest list name>. <seq num> is
 * optional.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int digest_cache_parse_digest_list(struct digest_cache *digest_cache,
					  char *path_str, char *filename,
					  void *data, size_t data_len)
{
	char *format, *next_sep;
	int ret = -EINVAL;

	if (!filename[0]) {
		filename = strrchr(path_str, '/');
		if (!filename)
			return ret;

		filename++;
	}

	format = filename;

	/*
	 * Since we expect that all files start with a digest list format, this
	 * check is reliable to detect <seq num>.
	 */
	if (filename[0] >= '0' && filename[0] <= '9') {
		format = strchr(filename, '-');
		if (!format)
			return ret;

		format++;
	}

	next_sep = strchr(format, '-');
	if (!next_sep)
		return ret;

	pr_debug("Parsing %s%s%s, format: %.*s, size: %ld\n", path_str,
		 filename[0] ? "/" : "", filename, (int)(next_sep - format),
		 format, data_len);

	if (!strncmp(format, "tlv-", 4))
		ret = digest_list_parse_tlv(digest_cache, data, data_len);
	else if (!strncmp(format, "rpm-", 4))
		ret = digest_list_parse_rpm(digest_cache, data, data_len);

	return ret;
}

/**
 * digest_cache_read_digest_list - Read a digest list
 * @work: Work structure
 *
 * This function is invoked by schedule_work() to read a digest list.
 *
 * It does not return a value, but stores the result in the passed structure.
 */
static void digest_cache_read_digest_list(struct work_struct *work)
{
	struct read_work *w = container_of(work, struct read_work, work);

	w->ret = kernel_read_file(w->file, 0, &w->data, INT_MAX, NULL,
				  READING_DIGEST_LIST);
}

/**
 * digest_cache_populate - Populate a digest cache from a digest list
 * @digest_cache: Digest cache
 * @digest_list_path: Path structure of the digest list
 * @path_str: Path string of the digest list
 * @filename: Digest list file name (can be an empty string)
 *
 * This function opens the digest list for reading it. Then, it schedules a
 * work to read the digest list and, once the work is done, it calls
 * digest_cache_strip_modsig() to strip a module-style appended signature and
 * digest_cache_parse_digest_list() for extracting and adding digests to the
 * digest cache.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_populate(struct digest_cache *digest_cache,
			  struct path *digest_list_path, char *path_str,
			  char *filename)
{
	struct file *file;
	void *data;
	size_t data_len;
	struct read_work w;
	int ret;

	file = dentry_open(digest_list_path, O_RDONLY, &init_cred);
	if (IS_ERR(file)) {
		pr_debug("Unable to open digest list %s%s%s, ret: %ld\n",
			 path_str, filename[0] ? "/" : "", filename,
			 PTR_ERR(file));
		return PTR_ERR(file);
	}

	digest_cache_to_file_sec(file, digest_cache);

	w.data = NULL;
	w.file = file;
	INIT_WORK_ONSTACK(&w.work, digest_cache_read_digest_list);

	schedule_work(&w.work);
	flush_work(&w.work);
	destroy_work_on_stack(&w.work);
	fput(file);

	ret = w.ret;
	data = w.data;

	if (ret < 0) {
		pr_debug("Unable to read digest list %s%s%s, ret: %d\n",
			 path_str, filename[0] ? "/" : "", filename, ret);
		return ret;
	}

	data_len = digest_cache_strip_modsig(data, ret);

	/* Digest list parsers initialize the hash table and add the digests. */
	ret = digest_cache_parse_digest_list(digest_cache, path_str, filename,
					     data, data_len);
	if (ret < 0)
		pr_debug("Error parsing digest list %s%s%s, ret: %d\n",
			 path_str, filename[0] ? "/" : "", filename, ret);

	vfree(data);
	return ret;
}
