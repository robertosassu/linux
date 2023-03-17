// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the tests of the digest_cache LSM.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fts.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "generators.h"

#include "../kselftest_harness.h"
#include "../../../../include/uapi/linux/xattr.h"

#define BASE_DIR_TEMPLATE "/tmp/digest_cache_test_dirXXXXXX"
#define DIGEST_LISTS_SUBDIR "digest_lists"
#define NUM_DIGEST_LISTS_PREFETCH MAX_WORKS

FIXTURE(shared_data) {
	char base_dir[sizeof(BASE_DIR_TEMPLATE)];
	char digest_lists_dir[sizeof(BASE_DIR_TEMPLATE) +
			      sizeof(DIGEST_LISTS_SUBDIR)];
	int base_dirfd, digest_lists_dirfd, kernfd, pathfd, cmd_len;
};

FIXTURE_SETUP(shared_data)
{
	char cmd[1024];
	int i, cmd_len;

	/* Create the base directory. */
	snprintf(self->base_dir, sizeof(self->base_dir), BASE_DIR_TEMPLATE);
	ASSERT_NE(NULL, mkdtemp(self->base_dir));

	/* Open base directory. */
	self->base_dirfd = open(self->base_dir, O_RDONLY | O_DIRECTORY);
	ASSERT_NE(-1, self->base_dirfd);

	/* Create the digest_lists subdirectory. */
	snprintf(self->digest_lists_dir, sizeof(self->digest_lists_dir),
		 "%s/%s", self->base_dir, DIGEST_LISTS_SUBDIR);
	ASSERT_EQ(0, mkdirat(self->base_dirfd, DIGEST_LISTS_SUBDIR, 0600));
	self->digest_lists_dirfd = openat(self->base_dirfd, DIGEST_LISTS_SUBDIR,
					  O_RDONLY | O_DIRECTORY);
	ASSERT_NE(-1, self->digest_lists_dirfd);

	/* Open kernel test interface. */
	self->kernfd = open(DIGEST_CACHE_TEST_INTERFACE, O_RDWR, 0600);
	ASSERT_NE(-1, self->kernfd);

	/* Open kernel digest list path interface. */
	self->pathfd = open(DIGEST_CACHE_PATH_INTERFACE, O_RDWR, 0600);
	ASSERT_NE(-1, self->pathfd);
	/* Write the path of the digest lists directory. */
	ASSERT_LT(0, write(self->pathfd, self->digest_lists_dir,
			   strlen(self->digest_lists_dir)));

	/* Ensure that no verifier is enabled at the beginning of a test. */
	for (i = 0; i < VERIF__LAST; i++) {
		cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s",
				   commands_str[DIGEST_CACHE_DISABLE_VERIF],
				   verifs_str[i]);
		ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));
	}
}

FIXTURE_TEARDOWN(shared_data)
{
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { self->base_dir, NULL };
	char cmd[1024];
	int cmd_len;

	/* Close digest_lists subdirectory. */
	close(self->digest_lists_dirfd);

	/* Close base directory. */
	close(self->base_dirfd);

	/* Delete files and directories. */
	fts = fts_open(paths, fts_flags, NULL);
	if (fts) {
		while ((ftsent = fts_read(fts)) != NULL) {
			switch (ftsent->fts_info) {
			case FTS_DP:
				rmdir(ftsent->fts_accpath);
				break;
			case FTS_F:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_DEFAULT:
				unlink(ftsent->fts_accpath);
				break;
			default:
				break;
			}
		}
	}

	/* Release digest cache reference, if the test was interrupted. */
	cmd_len = snprintf(cmd, sizeof(cmd), "%s",
			   commands_str[DIGEST_CACHE_PUT]);
	write(self->kernfd, cmd, cmd_len);

	/* Close kernel test interface. */
	close(self->kernfd);

	/* Close kernel digest list path interface. */
	close(self->pathfd);
}

static int query_test(int kernfd, char *base_dir, char *filename,
		      enum hash_algo algo, int start_number, int num_digests)
{
	u8 digest[MAX_DIGEST_SIZE] = { 0 };
	char digest_str[MAX_DIGEST_SIZE * 2 + 1] = { 0 };
	int digest_len = hash_digest_size[algo];
	char cmd[1024];
	int ret, i, cmd_len;

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s/%s",
			   commands_str[DIGEST_CACHE_GET], base_dir, filename);
	ret = write(kernfd, cmd, cmd_len);
	if (ret != cmd_len)
		return -errno;

	ret = 0;

	*(u32 *)digest = start_number;

	for (i = 0; i < num_digests; i++) {
		bin2hex(digest_str, digest, digest_len);

		cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s/%s|%s:%s",
				   commands_str[DIGEST_CACHE_LOOKUP], base_dir,
				   filename, hash_algo_name[algo], digest_str);
		ret = write(kernfd, cmd, cmd_len);
		if (ret != cmd_len) {
			ret = -errno;
			goto out;
		} else {
			ret = 0;
		}

		(*(u32 *)digest)++;
	}
out:
	cmd_len = snprintf(cmd, sizeof(cmd), "%s",
			   commands_str[DIGEST_CACHE_PUT]);
	write(kernfd, cmd, cmd_len);
	return ret;
}

static enum pgp_algos get_pgp_algo(enum hash_algo algo)
{
	long unsigned i;

	for (i = DIGEST_ALGO_MD5; i < ARRAY_SIZE(pgp_algo_mapping); i++)
		if (pgp_algo_mapping[i] == algo)
			return i;

	return DIGEST_ALGO_SHA224 + 1;
}

static void test_parser(struct _test_data_shared_data *self,
			struct __test_metadata *_metadata,
			char *digest_list_filename, char *filename,
			enum hash_algo algo, int start_number, int num_digests,
			unsigned int failure)
{
	int expected_ret = (failure) ? -ENOENT : 0;

	if (!strncmp(digest_list_filename, "tlv-", 4)) {
		ASSERT_EQ(0, gen_tlv_list(self->digest_lists_dirfd,
					  digest_list_filename, algo,
					  start_number, num_digests,
					  (enum tlv_failures)failure));
	} else if (!strncmp(digest_list_filename, "rpm-", 4)) {
		enum pgp_algos pgp_algo = get_pgp_algo(algo);

		if (pgp_algo == DIGEST_ALGO_SHA224 + 1)
			return;

		ASSERT_EQ(0, gen_rpm_list(self->digest_lists_dirfd,
					  digest_list_filename, algo, pgp_algo,
					  start_number, num_digests,
					  (enum rpm_failures)failure));
	}

	ASSERT_EQ(0, create_file(self->base_dirfd, filename,
				 digest_list_filename));
	ASSERT_EQ(expected_ret, query_test(self->kernfd, self->base_dir,
					   filename, algo, start_number,
					   num_digests));

	unlinkat(self->digest_lists_dirfd, digest_list_filename, 0);
	unlinkat(self->base_dirfd, filename, 0);
}

/*
 * Verify that the tlv digest list parser returns success on well-formatted
 * digest lists, for each defined hash algorithm.
 */
TEST_F(shared_data, tlv_parser_ok)
{
	enum hash_algo algo;

	/* Test every known algorithm. */
	for (algo = 0; algo < HASH_ALGO__LAST; algo++)
		test_parser(self, _metadata, "tlv-digest_list", "file", algo,
			    0, 5, TLV_NO_FAILURE);
}

/*
 * Verify that the tlv digest list parser returns failure on invalid digest
 * lists.
 */
TEST_F(shared_data, tlv_parser_error)
{
	enum tlv_failures failure;

	/* Test every failure. */
	for (failure = 0; failure < TLV_FAILURE__LAST; failure++)
		test_parser(self, _metadata, "tlv-digest_list", "file",
			    HASH_ALGO_SHA224, 0, 1, failure);
}

/*
 * Verify that the rpm digest list parser returns success on well-formatted
 * digest lists, for each defined hash algorithm.
 */
TEST_F(shared_data, rpm_parser_ok)
{
	enum hash_algo algo;

	/* Test every known algorithm. */
	for (algo = 0; algo < HASH_ALGO__LAST; algo++)
		test_parser(self, _metadata, "rpm-digest_list", "file", algo,
			    0, 5, RPM_NO_FAILURE);
}

/*
 * Verify that the rpm digest list parser returns failure on invalid digest
 * lists.
 */
TEST_F(shared_data, rpm_parser_error)
{
	enum rpm_failures failure;

	/* Test every failure. */
	for (failure = 0; failure < RPM_FAILURE__LAST; failure++)
		test_parser(self, _metadata, "rpm-digest_list", "file",
			    HASH_ALGO_SHA224, 0, 1, failure);
}

static void test_default_path(struct _test_data_shared_data *self,
			      struct __test_metadata *_metadata, bool file)
{
	char path[PATH_MAX];
	size_t path_len;

	if (file) {
		path_len = snprintf(path, sizeof(path),
				    "%s/%s/tlv-digest_list", self->base_dir,
				    DIGEST_LISTS_SUBDIR);
		ASSERT_LT(0, write(self->pathfd, path, path_len));
	}

	ASSERT_EQ(0, gen_tlv_list(self->digest_lists_dirfd, "tlv-digest_list",
				  HASH_ALGO_SHA1, 0, 1, TLV_NO_FAILURE));

	ASSERT_EQ(0, create_file(self->base_dirfd, "file", NULL));

	ASSERT_EQ(0, query_test(self->kernfd, self->base_dir, "file",
				HASH_ALGO_SHA1, 0, 1));
}

/*
 * Verify that the digest cache created from the default path (regular file)
 * can be retrieved and used for lookup.
 */
TEST_F(shared_data, default_path_file)
{
	test_default_path(self, _metadata, true);
}

/*
 * Verify that the digest cache created from the default path (directory)
 * can be retrieved and used for lookup.
 */
TEST_F(shared_data, default_path_dir)
{
	test_default_path(self, _metadata, false);
}

static void test_file_changes(struct _test_data_shared_data *self,
			      struct __test_metadata *_metadata,
			      enum file_changes change)
{
	char digest_list_filename[] = "tlv-digest_list";
	char digest_list_filename_new[] = "tlv-digest_list6";
	char digest_list_path[sizeof(self->digest_lists_dir) +
			      sizeof(digest_list_filename)];
	int fd;

	ASSERT_EQ(0, gen_tlv_list(self->digest_lists_dirfd, digest_list_filename,
				  HASH_ALGO_SHA1, 0, 1, TLV_NO_FAILURE));

	ASSERT_EQ(0, create_file(self->base_dirfd, "file", digest_list_filename));

	ASSERT_EQ(0, query_test(self->kernfd, self->base_dir, "file",
				HASH_ALGO_SHA1, 0, 1));

	switch (change) {
	case FILE_WRITE:
		fd = openat(self->digest_lists_dirfd, digest_list_filename,
			    O_WRONLY);
		ASSERT_NE(-1, fd);

		ASSERT_EQ(4, write(fd, "1234", 4));
		close(fd);
		break;
	case FILE_TRUNCATE:
		snprintf(digest_list_path, sizeof(digest_list_path),
			 "%s/%s", self->digest_lists_dir, digest_list_filename);
		ASSERT_EQ(0, truncate(digest_list_path, 4));
		break;
	case FILE_UNLINK:
		ASSERT_EQ(0, unlinkat(self->digest_lists_dirfd,
				      digest_list_filename, 0));
		break;
	case FILE_RENAME:
		ASSERT_EQ(0, renameat(self->digest_lists_dirfd,
				      digest_list_filename,
				      self->digest_lists_dirfd,
				      digest_list_filename_new));
		break;
	default:
		break;
	}

	ASSERT_NE(0, query_test(self->kernfd, self->base_dir, "file",
				HASH_ALGO_SHA1, 0, 1));
}

/*
 * Verify that operations on a digest list cause a reset of the digest cache,
 * and that the digest is not found in the invalid/missing digest list.
 */
TEST_F(shared_data, file_reset)
{
	enum file_changes change;

	/* Test for every file change. */
	for (change = 0; change < FILE_CHANGE__LAST; change++)
		test_file_changes(self, _metadata, change);
}

static void query_test_with_failures(struct _test_data_shared_data *self,
				     struct __test_metadata *_metadata,
				     int start_number, int num_digests,
				     int *removed, int num_removed)
{
	int i, j, expected_ret;

	for (i = start_number; i < start_number + num_digests; i++) {
		expected_ret = 0;

		for (j = 0; j < num_removed; j++) {
			if (removed[j] == i) {
				expected_ret = -ENOENT;
				break;
			}
		}

		ASSERT_EQ(expected_ret, query_test(self->kernfd, self->base_dir,
						   "file", HASH_ALGO_SHA1, i,
						   1));
	}
}

/*
 * Verify that changes in the digest list directory are monitored and that
 * a digest cannot be found if the respective digest list file has been moved
 * away from the directory, and that a digest can be found if the respective
 * digest list has been moved/created in the directory.
 */
TEST_F(shared_data, dir_reset)
{
	char digest_list_filename[NAME_MAX + 1];
	int i, removed[10];

	for (i = 0; i < 10; i++) {
		snprintf(digest_list_filename, sizeof(digest_list_filename),
			 "tlv-digest_list%d", i);
		ASSERT_EQ(0, gen_tlv_list(self->digest_lists_dirfd,
					  digest_list_filename, HASH_ALGO_SHA1,
					  i, 1, TLV_NO_FAILURE));
	}

	ASSERT_EQ(0, create_file(self->base_dirfd, "file", NULL));

	query_test_with_failures(self, _metadata, 0, 10, removed, 0);

	ASSERT_EQ(0, unlinkat(self->digest_lists_dirfd, "tlv-digest_list7", 0));

	removed[0] = 7;

	query_test_with_failures(self, _metadata, 0, 10, removed, 1);

	ASSERT_EQ(0, renameat(self->digest_lists_dirfd, "tlv-digest_list6",
			      self->base_dirfd, "tlv-digest_list6"));

	removed[1] = 6;

	query_test_with_failures(self, _metadata, 0, 10, removed, 2);

	ASSERT_EQ(0, renameat(self->base_dirfd, "tlv-digest_list6",
			      self->digest_lists_dirfd, "tlv-digest_list6"));

	query_test_with_failures(self, _metadata, 0, 10, removed, 1);

	ASSERT_EQ(0, gen_tlv_list(self->digest_lists_dirfd, "tlv-digest_list10",
				  HASH_ALGO_SHA1, 10, 1, TLV_NO_FAILURE));

	query_test_with_failures(self, _metadata, 0, 11, removed, 1);
}

static void _check_verif_data(struct _test_data_shared_data *self,
			      struct __test_metadata *_metadata,
			      char *digest_list_filename, int num,
			      enum hash_algo algo, bool check_dir)
{
	char digest_list_filename_kernel[NAME_MAX + 1];
	char cmd[1024], number[20];
	u8 digest[MAX_DIGEST_SIZE] = { 0 };
	char digest_str[MAX_DIGEST_SIZE * 2 + 1] = { 0 };
	int len, cmd_len;

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s/file",
			   commands_str[DIGEST_CACHE_GET], self->base_dir);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	/*
	 * If a directory digest cache was requested, we need to do a lookup,
	 * to make the kernel module retrieve verification data from the digest
	 * cache of the directory entry.
	 */
	if (check_dir) {
		*(u32 *)digest = num;

		bin2hex(digest_str, digest, hash_digest_size[algo]);

		cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s/file|%s:%s",
				   commands_str[DIGEST_CACHE_LOOKUP],
				   self->base_dir, hash_algo_name[algo],
				   digest_str);
		ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));
	}

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s",
			   commands_str[DIGEST_CACHE_SET_VERIF],
			   verifs_str[VERIF_FILENAMES]);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	ASSERT_LT(0, read(self->kernfd, digest_list_filename_kernel,
			  sizeof(digest_list_filename_kernel)));
	ASSERT_EQ(0, strcmp(digest_list_filename, digest_list_filename_kernel));

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s",
			   commands_str[DIGEST_CACHE_SET_VERIF],
			   verifs_str[VERIF_NUMBER]);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	len = read(self->kernfd, number, sizeof(number) - 1);
	ASSERT_LT(0, len);
	number[len] = '\0';
	ASSERT_EQ(num, atoi(number));

	cmd_len = snprintf(cmd, sizeof(cmd), "%s",
			   commands_str[DIGEST_CACHE_PUT]);
	write(self->kernfd, cmd, cmd_len);
}

static void check_verif_data(struct _test_data_shared_data *self,
			     struct __test_metadata *_metadata)
{
	char digest_list_filename[NAME_MAX + 1];
	char cmd[1024];
	int i, cmd_len;

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s",
			   commands_str[DIGEST_CACHE_ENABLE_VERIF],
			   verifs_str[VERIF_FILENAMES]);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s",
			   commands_str[DIGEST_CACHE_ENABLE_VERIF],
			   verifs_str[VERIF_NUMBER]);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	/*
	 * Reverse order is intentional, so that directory entries are created
	 * in the opposite order as when they are searched (when prefetching is
	 * requested).
	 */
	for (i = 10; i >= 0; i--) {
		snprintf(digest_list_filename, sizeof(digest_list_filename),
			 "%d-tlv-digest_list%d", i, i);
		ASSERT_EQ(0, gen_tlv_list(self->digest_lists_dirfd,
					  digest_list_filename, HASH_ALGO_SHA1,
					  i, 1, TLV_NO_FAILURE));

		ASSERT_EQ(0, create_file(self->base_dirfd, "file",
					 digest_list_filename));

		_check_verif_data(self, _metadata, digest_list_filename, i,
				  HASH_ALGO_SHA1, false);

		ASSERT_EQ(0, unlinkat(self->base_dirfd, "file", 0));
	}

	ASSERT_EQ(0, create_file(self->base_dirfd, "file", NULL));

	for (i = 0; i < 11; i++) {
		snprintf(digest_list_filename, sizeof(digest_list_filename),
			 "%d-tlv-digest_list%d", i, i);
		_check_verif_data(self, _metadata, digest_list_filename, i,
				  HASH_ALGO_SHA1, true);
	}

	ASSERT_EQ(0, unlinkat(self->base_dirfd, "file", 0));
}

/*
 * Verify that the correct verification data can be retrieved from the digest
 * caches (without digest list prefetching).
 */
TEST_F(shared_data, verif_data_no_prefetch)
{
	check_verif_data(self, _metadata);
}

/*
 * Verify that the correct verification data can be retrieved from the digest
 * caches (with digest list prefetching).
 */
TEST_F(shared_data, verif_data_prefetch)
{
	ASSERT_EQ(0, lsetxattr(self->base_dir, XATTR_NAME_DIG_PREFETCH,
			       "1", 1, 0));

	check_verif_data(self, _metadata);
}

static void check_prefetch_list(struct _test_data_shared_data *self,
				struct __test_metadata *_metadata,
				int start_number, int end_number)
{
	char digest_list_filename[NAME_MAX + 1], filename[NAME_MAX + 1];
	char digest_lists[1024], digest_lists_kernel[1024] = { 0 };
	char cmd[1024];
	int i, cmd_len;

	snprintf(filename, sizeof(filename), "file%d", end_number);
	snprintf(digest_list_filename, sizeof(digest_list_filename),
		 "%d-tlv-digest_list%d", end_number, end_number);
	ASSERT_EQ(0, create_file(self->base_dirfd, filename,
				 digest_list_filename));

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s/%s",
			   commands_str[DIGEST_CACHE_GET], self->base_dir,
			   filename);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	ASSERT_LT(0, read(self->kernfd, digest_lists, sizeof(digest_lists)));

	for (i = start_number; i <= end_number; i++) {
		if (digest_lists_kernel[0])
			strcat(digest_lists_kernel, ",");

		snprintf(digest_list_filename, sizeof(digest_list_filename),
			 "%d-tlv-digest_list%d", i, i);
		strcat(digest_lists_kernel, digest_list_filename);
	}

	ASSERT_EQ(0, strcmp(digest_lists, digest_lists_kernel));

	ASSERT_EQ(0, unlinkat(self->base_dirfd, filename, 0));

	cmd_len = snprintf(cmd, sizeof(cmd), "%s",
			   commands_str[DIGEST_CACHE_PUT]);
	write(self->kernfd, cmd, cmd_len);
}

static void check_prefetch_list_async(struct _test_data_shared_data *self,
				      struct __test_metadata *_metadata)
{
	char digest_list_filename[NAME_MAX + 1], filename[NAME_MAX + 1];
	char digest_lists[1024], digest_lists_kernel[1024] = { 0 };
	char cmd[1024];
	int i, cmd_len;

	for (i = 0; i < NUM_DIGEST_LISTS_PREFETCH; i++) {
		snprintf(filename, sizeof(filename), "file%d",
			 NUM_DIGEST_LISTS_PREFETCH - 1 - i);
		snprintf(digest_list_filename, sizeof(digest_list_filename),
			 "%d-tlv-digest_list%d", i, i);
		ASSERT_EQ(0, create_file(self->base_dirfd, filename,
					 digest_list_filename));
	}

	/* Do batch of get/put to test the kernel for concurrent requests. */
	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s/file|%d|%d",
			   commands_str[DIGEST_CACHE_GET_PUT_ASYNC],
			   self->base_dir, 0, NUM_DIGEST_LISTS_PREFETCH - 1);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	ASSERT_LT(0, read(self->kernfd, digest_lists, sizeof(digest_lists)));

	for (i = 0; i < NUM_DIGEST_LISTS_PREFETCH; i++) {
		if (digest_lists_kernel[0])
			strcat(digest_lists_kernel, ",");

		snprintf(digest_list_filename, sizeof(digest_list_filename),
			 "%d-tlv-digest_list%d", i, i);
		strcat(digest_lists_kernel, digest_list_filename);
	}

	ASSERT_EQ(0, strcmp(digest_lists, digest_lists_kernel));
}

static void prepare_prefetch(struct _test_data_shared_data *self,
			     struct __test_metadata *_metadata)
{
	char digest_list_filename[NAME_MAX + 1];
	char cmd[1024];
	int i, cmd_len;

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s",
			   commands_str[DIGEST_CACHE_ENABLE_VERIF],
			   verifs_str[VERIF_PREFETCH]);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	cmd_len = snprintf(cmd, sizeof(cmd), "%s|%s",
			   commands_str[DIGEST_CACHE_SET_VERIF],
			   verifs_str[VERIF_PREFETCH]);
	ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));

	for (i = NUM_DIGEST_LISTS_PREFETCH - 1; i >= 0; i--) {
		snprintf(digest_list_filename, sizeof(digest_list_filename),
			 "%d-tlv-digest_list%d", i, i);
		ASSERT_EQ(0, gen_tlv_list(self->digest_lists_dirfd,
					  digest_list_filename, HASH_ALGO_SHA1,
					  i, 1, TLV_NO_FAILURE));
	}

	ASSERT_EQ(0, fsetxattr(self->digest_lists_dirfd,
			       XATTR_NAME_DIG_PREFETCH, "1", 1, 0));
}

/*
 * Verify that digest lists are prefetched when requested, in the correct order
 * (synchronous version).
 */
TEST_F(shared_data, prefetch_sync)
{
	char cmd[1024];
	int i, cmd_len;

	prepare_prefetch(self, _metadata);

	for (i = 2; i < NUM_DIGEST_LISTS_PREFETCH; i += 3) {
		check_prefetch_list(self, _metadata, i - 2, i);

		cmd_len = snprintf(cmd, sizeof(cmd), "%s",
				commands_str[DIGEST_CACHE_RESET_PREFETCH_BUF]);
		ASSERT_EQ(cmd_len, write(self->kernfd, cmd, cmd_len));
	}
}

/*
 * Verify that digest lists are prefetched when requested, in the correct order
 * (asynchronous version).
 */
TEST_F(shared_data, prefetch_async)
{
	prepare_prefetch(self, _metadata);

	check_prefetch_list_async(self, _metadata);
}

TEST_HARNESS_MAIN
