// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Functions to load digest lists.
 */

#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ima.h>

#include "diglim.h"

struct readdir_callback {
	struct dir_context ctx;
	struct path *path;
};

static bool digest_list_supported_by_kernel(const char *filename)
{
	char *type_start, *format_start, *format_end;

	type_start = strchr(filename, '-');
	if (!type_start++)
		return false;

	format_start = strchr(type_start, '-');
	if (!format_start++)
		return false;

	format_end = strchr(format_start, '-');
	if (!format_end)
		return false;

	if (format_end - format_start != strlen("compact") ||
	    strncmp(format_start, "compact", format_end - format_start))
		return false;

	return true;
}

static int __init digest_list_load(struct dir_context *__ctx, const char *name,
				   int namelen, loff_t offset, u64 ino,
				   unsigned int d_type)
{
	struct readdir_callback *ctx = container_of(__ctx, typeof(*ctx), ctx);
	int ret;

	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return 0;

	if (!digest_list_supported_by_kernel(name))
		return 0;

	ret = digest_list_read(ctx->path, (char *)name, DIGEST_LIST_ADD);
	if (ret < 0)
		return 0;

	return 0;
}

static void digest_list_exec_parser(void)
{
	char *argv[4] = {NULL}, *envp[1] = {NULL};

	argv[0] = (char *)CONFIG_DIGLIM_UPLOADER_PATH;
	argv[1] = "add";
	argv[2] = CONFIG_DIGLIM_DIGEST_LISTS_DIR;

	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

void __init digest_lists_load(void)
{
	struct file *file;
	struct readdir_callback buf = {
		.ctx.actor = digest_list_load,
	};

	file = filp_open(CONFIG_DIGLIM_DIGEST_LISTS_DIR, O_RDONLY, 0);
	if (IS_ERR(file))
		return;

	buf.path = &file->f_path;
	iterate_dir(file, &buf.ctx);
	fput(file);

	digest_list_exec_parser();
}
