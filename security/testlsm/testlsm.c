// SPDX-License-Identifier: GPL-2.0-only
/*
 * TestLSM
 *
 * Copyright 2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#define pr_fmt(fmt) "TestLSM: " fmt

#include <linux/lsm_hooks.h>
#include <linux/xattr.h>

#define XATTR_TESTLSM_SUFFIX TESTLSM_NAME
#define XATTR_NAME_TESTLSM XATTR_SECURITY_PREFIX XATTR_TESTLSM_SUFFIX
#define XATTR_TESTLSM_SUFFIX2 TESTLSM_NAME "2"
#define XATTR_NAME_TESTLSM2 XATTR_SECURITY_PREFIX XATTR_TESTLSM_SUFFIX2

#define IMA_UUID "28b23254-9467-44c0-b6ba-34b12e85a26d"
#define IMA_UUID2 "28b23254-9467-44c0-b6ba-34b12e85a26e"
#define IMA_UUID3 "28b23254-9467-44c0-b6ba-34b12e85a26f"

struct lsm_blob_sizes VAR_BLOB_SIZES __ro_after_init = {
#if defined XATTR && !defined XATTR2
	.lbs_xattr_count = 1,
#else
#if defined XATTR && defined XATTR2
	.lbs_xattr_count = 2,
#else
	.lbs_xattr_count = 0,
#endif
#endif
};

static int testlsm_inode_init_security(struct inode *inode,
				struct inode *dir, const struct qstr *qstr,
				struct xattr *xattrs, int *num_filled_xattrs)
{
#if defined LSMBUG || defined LSMBUG2
	uuid_t ima_uuid, ima_uuid3;
#endif
	int ret = -EOPNOTSUPP;
#if defined XATTR && !defined DISABLED_STATE
	struct xattr *xattr = NULL;
#ifdef XATTR2
	struct xattr *xattr2 = NULL;
#endif
#if defined LSMBUG || defined LSMBUG2
	ret = uuid_parse(IMA_UUID, &ima_uuid);
	if (ret < 0)
		return ret;

	ret = uuid_parse(IMA_UUID3, &ima_uuid3);
	if (ret < 0)
		return ret;

#ifdef LSMBUG2
	if (uuid_equal(&ima_uuid, &inode->i_sb->s_uuid) ||
	    uuid_equal(&ima_uuid3, &inode->i_sb->s_uuid) ||
	    !strcmp(inode->i_sb->s_type->name, "reiserfs"))
		return 0;
#endif
#endif
	if (xattrs)
		xattr = lsm_get_xattr_slot(xattrs, num_filled_xattrs);

	if (xattr) {
		xattr->name = XATTR_TESTLSM_SUFFIX;
	}

#ifdef XATTR2
	if (xattrs)
		xattr2 = lsm_get_xattr_slot(xattrs, num_filled_xattrs);

	if (xattr2) {
		xattr2->name = XATTR_TESTLSM_SUFFIX2;
	}
#endif

#ifdef LSMBUG
	if (uuid_equal(&ima_uuid, &inode->i_sb->s_uuid) ||
	    uuid_equal(&ima_uuid3, &inode->i_sb->s_uuid) ||
	    !strcmp(inode->i_sb->s_type->name, "reiserfs"))
		xattr->name = NULL;
#endif
	if (xattr) {
		xattr->value = kstrdup(TESTLSM_NAME, GFP_NOFS);
		if (!xattr->value)
			return -ENOMEM;

		xattr->value_len = sizeof(TESTLSM_NAME);
	}

#ifdef XATTR2
	if (xattr2) {
		xattr2->value = kstrdup(TESTLSM_NAME, GFP_NOFS);
		if (!xattr2->value)
			return -ENOMEM;

		xattr2->value_len = sizeof(TESTLSM_NAME);
	}
#endif

	ret = 0;
#endif
	return ret;
}

static struct security_hook_list testlsm_hook[] __ro_after_init = {
	LSM_HOOK_INIT(inode_init_security, testlsm_inode_init_security),
};

static int __init testlsm_init(void)
{
	security_add_hooks(testlsm_hook, ARRAY_SIZE(testlsm_hook),
			   TESTLSM_NAME);
	return 0;
}

DEFINE_LSM(testlsm) = {
	.name = TESTLSM_NAME,
	.init = testlsm_init,
	.blobs = &VAR_BLOB_SIZES,
};
