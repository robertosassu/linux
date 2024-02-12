// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Manage digest caches from directories.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include <linux/init_task.h>

#include "internal.h"

/**
 * digest_cache_dir_iter - Digest cache directory iterator
 * @__ctx: iterate_dir() context
 * @name: Name of file in the accessed directory
 * @namelen: String length of @name
 * @offset: Current position in the directory stream (see man readdir)
 * @ino: Inode number
 * @d_type: File type
 *
 * This function stores the names of the files in the containing directory in
 * a linked list. If they are in the format <seq num>-<format>-<name>, this
 * function orders them by seq num, so that digest lists are processed in the
 * desired order. Otherwise, if <seq num>- is not included, it adds the name at
 * the end of the list.
 *
 * Return: True to continue processing, false to stop.
 */
static bool digest_cache_dir_iter(struct dir_context *__ctx, const char *name,
				  int namelen, loff_t offset, u64 ino,
				  unsigned int d_type)
{
	struct readdir_callback *ctx = container_of(__ctx, typeof(*ctx), ctx);
	struct dir_entry *new_entry, *p;
	unsigned int seq_num;
	char *separator;
	int ret;

	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return true;

	if (d_type != DT_REG)
		return true;

	new_entry = kmalloc(sizeof(*new_entry) + namelen + 1, GFP_KERNEL);
	if (!new_entry)
		return false;

	memcpy(new_entry->name, name, namelen);
	new_entry->name[namelen] = '\0';
	new_entry->seq_num = UINT_MAX;
	new_entry->digest_cache = NULL;
	mutex_init(&new_entry->digest_cache_mutex);
	new_entry->prefetched = false;

	if (new_entry->name[0] < '0' || new_entry->name[0] > '9')
		goto out;

	separator = strchr(new_entry->name, '-');
	if (!separator)
		goto out;

	*separator = '\0';
	ret = kstrtouint(new_entry->name, 10, &seq_num);
	*separator = '-';
	if (ret < 0)
		goto out;

	new_entry->seq_num = seq_num;

	list_for_each_entry(p, ctx->head, list) {
		if (seq_num <= p->seq_num) {
			list_add(&new_entry->list, p->list.prev);
			pr_debug("Added %s before %s in dir list\n",
				 new_entry->name, p->name);
			return true;
		}
	}
out:
	list_add_tail(&new_entry->list, ctx->head);
	pr_debug("Added %s to tail of dir list\n", new_entry->name);
	return true;
}

/**
 * digest_cache_dir_create - Create a directory digest cache
 * @digest_cache: Digest cache
 * @digest_list_path: Path structure of the digest list directory
 *
 * This function iterates over the entries of a directory, and creates a linked
 * list of file names from that directory.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_dir_create(struct digest_cache *digest_cache,
			    struct path *digest_list_path)
{
	struct file *dir_file;
	struct readdir_callback buf = {
		.ctx.actor = digest_cache_dir_iter,
	};
	int ret;

	dir_file = dentry_open(digest_list_path, O_RDONLY, &init_cred);
	if (IS_ERR(dir_file)) {
		pr_debug("Cannot access %s, ret: %ld\n", digest_cache->path_str,
			 PTR_ERR(dir_file));
		return PTR_ERR(dir_file);
	}

	buf.head = &digest_cache->dir_entries;
	ret = iterate_dir(dir_file, &buf.ctx);
	if (ret < 0)
		pr_debug("Failed to iterate directory %s\n",
			 digest_cache->path_str);

	fput(dir_file);
	return ret;
}

/**
 * digest_cache_dir_lookup_digest - Lookup a digest
 * @dentry: Dentry of the file whose digest is looked up
 * @digest_list_path: Path structure of the digest list directory
 * @digest_cache: Digest cache
 * @digest: Digest to search
 * @algo: Algorithm of the digest to search
 * @filename: File name of the digest list to search
 *
 * This function iterates over the linked list created by
 * digest_cache_dir_create() and looks up the digest in the digest cache of
 * each entry.
 *
 * Return: A digest_cache_found_t value if the digest if found, zero otherwise.
 */
digest_cache_found_t
digest_cache_dir_lookup_digest(struct dentry *dentry,
			       struct path *digest_list_path,
			       struct digest_cache *digest_cache, u8 *digest,
			       enum hash_algo algo)
{
	struct digest_cache *cache;
	struct dir_entry *dir_entry;
	int ret;

	list_for_each_entry(dir_entry, &digest_cache->dir_entries, list) {
		mutex_lock(&dir_entry->digest_cache_mutex);
		if (!dir_entry->digest_cache) {
			cache = digest_cache_create(dentry, digest_list_path,
						    digest_cache->path_str,
						    dir_entry->name, false,
						    false);
			/* Ignore digest caches that cannot be instantiated. */
			if (!cache) {
				mutex_unlock(&dir_entry->digest_cache_mutex);
				continue;
			}

			/* Consume extra ref. from digest_cache_create(). */
			dir_entry->digest_cache = cache;
			/* Digest list was read, mark entry as prefetched. */
			dir_entry->prefetched = true;
		}
		mutex_unlock(&dir_entry->digest_cache_mutex);

		ret = digest_cache_htable_lookup(dentry,
						 dir_entry->digest_cache,
						 digest, algo);
		if (!ret)
			return (digest_cache_found_t)dir_entry->digest_cache;
	}

	return 0UL;
}

/**
 * digest_cache_dir_lookup_filename - Lookup a digest list
 * @dentry: Dentry of the file whose digest list is looked up
 * @digest_list_path: Path structure of the digest list directory
 * @digest_cache: Digest cache
 * @filename: File name of the digest list to search
 *
 * This function iterates over the linked list created by
 * digest_cache_dir_create() and looks up a digest list with a matching file
 * name among the entries. If there is no match, it prefetches (reads) the
 * current digest list. Otherwise, it returns the digest cache pointer from
 * digest_cache_create() to the caller.
 *
 * Return: A digest cache pointer if the digest list if found, NULL otherwise.
 */
struct digest_cache *
digest_cache_dir_lookup_filename(struct dentry *dentry,
				 struct path *digest_list_path,
				 struct digest_cache *digest_cache,
				 char *filename)
{
	struct digest_cache *cache;
	struct dir_entry *dir_entry;
	bool filename_found;

	list_for_each_entry(dir_entry, &digest_cache->dir_entries, list) {
		mutex_lock(&dir_entry->digest_cache_mutex);
		filename_found = !strcmp(dir_entry->name, filename);
		if (!filename_found && dir_entry->prefetched) {
			mutex_unlock(&dir_entry->digest_cache_mutex);
			continue;
		}

		cache = digest_cache_create(dentry, digest_list_path,
					    digest_cache->path_str,
					    dir_entry->name, false,
					    filename_found ? false : true);

		dir_entry->prefetched = true;
		mutex_unlock(&dir_entry->digest_cache_mutex);

		if (filename_found)
			return cache;
	}

	return NULL;
}

/**
 * digest_cache_dir_free - Free the stored file list and put digest caches
 * @digest_cache: Digest cache
 *
 * This function frees the file list created by digest_cache_create(), and puts
 * the digest cache if a reference exists.
 */
void digest_cache_dir_free(struct digest_cache *digest_cache)
{
	struct dir_entry *p, *q;

	list_for_each_entry_safe(p, q, &digest_cache->dir_entries, list) {
		if (p->digest_cache)
			digest_cache_put(p->digest_cache);

		list_del(&p->list);
		kfree(p);
	}
}
