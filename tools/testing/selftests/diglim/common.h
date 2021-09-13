/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of common.c
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
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/hash_info.h>

#define BUFFER_SIZE 1024

#define INTEGRITY_DIR "/sys/kernel/security/integrity"
#define DIGEST_LIST_DIR INTEGRITY_DIR "/diglim"
#define DIGEST_QUERY_PATH DIGEST_LIST_DIR "/digest_query"
#define DIGEST_LABEL_PATH DIGEST_LIST_DIR "/digest_list_label"
#define DIGEST_LIST_ADD_PATH DIGEST_LIST_DIR "/digest_list_add"
#define DIGEST_LIST_DEL_PATH DIGEST_LIST_DIR "/digest_list_del"
#define DIGEST_LISTS_LOADED_PATH DIGEST_LIST_DIR "/digest_lists_loaded"
#define DIGESTS_COUNT DIGEST_LIST_DIR "/digests_count"

int write_buffer(char *path, char *buffer, size_t buffer_len, int uid);
int read_buffer(char *path, char **buffer, size_t *buffer_len, bool alloc,
		bool is_char);
int copy_file(char *src_path, char *dst_path);
