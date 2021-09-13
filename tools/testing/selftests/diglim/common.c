// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common functions.
 */

#include <sys/random.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/hash_info.h>

#include "common.h"

int write_buffer(char *path, char *buffer, size_t buffer_len, int uid)
{
	ssize_t to_write = buffer_len, written = 0;
	int ret = 0, ret_seteuid, fd, cur_uid = geteuid();
	int open_flags = O_WRONLY;
	struct stat st;

	if (stat(path, &st) == -1)
		open_flags |= O_CREAT;

	fd = open(path, open_flags, 0644);
	if (fd < 0)
		return -errno;

	if (uid >= 0) {
		ret_seteuid = seteuid(uid);
		if (ret_seteuid < 0)
			return ret_seteuid;
	}

	while (to_write) {
		written = write(fd, buffer + buffer_len - to_write, to_write);
		if (written <= 0) {
			ret = -errno;
			break;
		}

		to_write -= written;
	}

	if (uid >= 0) {
		ret_seteuid = seteuid(cur_uid);
		if (ret_seteuid < 0)
			return ret_seteuid;
	}

	close(fd);
	return ret;
}

int read_buffer(char *path, char **buffer, size_t *buffer_len, bool alloc,
		bool is_char)
{
	ssize_t len = 0, read_len;
	int ret = 0, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	if (alloc) {
		*buffer = NULL;
		*buffer_len = 0;
	}

	while (1) {
		if (alloc) {
			if (*buffer_len == len) {
				*buffer_len += BUFFER_SIZE;
				*buffer = realloc(*buffer, *buffer_len + 1);
				if (!*buffer) {
					ret = -ENOMEM;
					goto out;
				}
			}
		}

		read_len = read(fd, *buffer + len, *buffer_len - len);
		if (read_len < 0) {
			ret = -errno;
			goto out;
		}

		if (!read_len)
			break;

		len += read_len;
	}

	*buffer_len = len;
	if (is_char)
		(*buffer)[(*buffer_len)++] = '\0';
out:
	close(fd);
	if (ret < 0) {
		if (alloc) {
			free(*buffer);
			*buffer = NULL;
		}
	}

	return ret;
}

int copy_file(char *src_path, char *dst_path)
{
	char *buffer;
	size_t buffer_len;
	int ret;

	ret = read_buffer(src_path, &buffer, &buffer_len, true, false);
	if (!ret) {
		ret = write_buffer(dst_path, buffer, buffer_len, -1);
		free(buffer);
	}

	return ret;
}
