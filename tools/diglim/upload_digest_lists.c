// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Run parsers of digest list formats not recognizable by the kernel.
 */

#include <stdio.h>
#include <errno.h>
#include <fts.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <linux/magic.h>

#define MOUNT_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME)
#define PROCFS_MNTPOINT "/proc"
#define SYSFS_MNTPOINT "/sys"
#define SECURITYFS_MNTPOINT SYSFS_MNTPOINT "/kernel/security"
#define DIGLIM_DIR SECURITYFS_MNTPOINT "/integrity/diglim"

struct format_entry {
	struct format_entry *next;
	char *format;
};

struct format_entry *head;
bool procfs_mounted;
bool sysfs_mounted;
bool securityfs_mounted;

int add_format_parser(char *path)
{
	char *name;
	char *type_start, *format_start, *format_end;
	struct format_entry *cur, *new;
	int ret = 0;

	name = strrchr(path, '/');
	if (!name)
		return -EINVAL;

	name++;

	type_start = strchr(name, '-');
	if (!type_start++)
		return 0;

	format_start = strchr(type_start, '-');
	if (!format_start++)
		return 0;

	format_end = strchr(format_start, '-');
	if (!format_end)
		return 0;

	if (!strncmp(format_start, "compact", format_end - format_start))
		return 0;

	cur = head;

	while (cur) {
		if (!strncmp(format_start, cur->format,
			     format_end - format_start))
			goto out;

		cur = cur->next;
	}

	new = malloc(sizeof(*new));
	if (!new) {
		ret = -ENOMEM;
		goto out;
	}

	new->format = strndup(format_start, format_end - format_start);
	if (!new->format) {
		ret = -ENOMEM;
		goto out;
	}

	new->next = head;
	head = new;
out:
	if (ret < 0)
		free(new);

	return ret;
}

void free_list(void)
{
	struct format_entry *cur = head, *tmp;

	while (cur) {
		tmp = cur;
		cur = tmp->next;
		free(tmp->format);
		free(tmp);
	}
}

static int mount_filesystems(void)
{
	struct stat st;
	struct statfs stf;
	int ret;

	if (stat("/proc/self", &st) == -1 ||
	    statfs("/proc/self", &stf) == -1 || stf.f_type != 0x9fa0) {
		ret = mount(PROCFS_MNTPOINT, PROCFS_MNTPOINT, "proc",
			    MOUNT_FLAGS, NULL);
		if (ret < 0) {
			printf("Cannot mount procfs\n");
			return ret;
		}

		procfs_mounted = true;
	}

	if (stat(SECURITYFS_MNTPOINT, &st) == -1 ||
	    statfs(SYSFS_MNTPOINT, &stf) == -1 ||
	    stf.f_type != 0x62656572) {
		ret = mount(SYSFS_MNTPOINT, SYSFS_MNTPOINT, "sysfs",
			    MOUNT_FLAGS, NULL);
		if (ret < 0) {
			printf("Cannot mount sysfs\n");
			return ret;
		}

		sysfs_mounted = true;
	}

	if (stat(DIGLIM_DIR, &st) == -1 ||
	    statfs(SECURITYFS_MNTPOINT, &stf) == -1 ||
	    stf.f_type != 0x73636673) {
		ret = mount(SECURITYFS_MNTPOINT, SECURITYFS_MNTPOINT,
			    "securityfs", MOUNT_FLAGS, NULL);
		if (ret < 0) {
			printf("Cannot mount securityfs\n");
			return ret;
		}

		securityfs_mounted = true;
	}

	return 0;
}

static void umount_filesystems(void)
{
	if (procfs_mounted)
		umount(PROCFS_MNTPOINT);
	if (securityfs_mounted)
		umount(SECURITYFS_MNTPOINT);
	if (sysfs_mounted)
		umount(SYSFS_MNTPOINT);
}

int main(int argc, char *argv[])
{
	char *paths[2] = { NULL, NULL };
	struct format_entry *cur;
	char parser_path[PATH_MAX], *sep;
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	int ret;

	if (argc != 3) {
		printf("Usage: %s add|del <digest list path>\n", argv[0]);
		return -EINVAL;
	}

	paths[0] = argv[2];

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts)
		return -EACCES;

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			ret = add_format_parser(ftsent->fts_path);
			if (ret < 0)
				printf("Cannot upload %s\n", ftsent->fts_path);

			break;
		default:
			break;
		}
	}

	fts_close(fts);
	fts = NULL;

	ret = mount_filesystems();
	if (ret < 0)
		goto out;

	ret = readlink("/proc/self/exe", parser_path, sizeof(parser_path));
	if (ret < 0)
		goto out;

	sep = strrchr(parser_path, '/');
	if (!sep++) {
		ret = -ENOENT;
		goto out;
	}

	cur = head;

	while (cur) {
		if (fork() == 0) {
			snprintf(sep, sizeof(parser_path) - (sep - parser_path),
				 "%s_parser", cur->format);
			return execlp(parser_path, parser_path, argv[1],
				      argv[2], NULL);
		}

		wait(NULL);
		cur = cur->next;
	}

out:
	free_list();
	umount_filesystems();
	return ret;
}
