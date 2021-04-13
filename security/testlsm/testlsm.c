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
#define XATTR_NAME_TESTLSM XATTR_SECURITY_PREFIX TESTLSM_NAME

#define IMA_UUID "28b23254-9467-44c0-b6ba-34b12e85a26d"
#define IMA_UUID2 "28b23254-9467-44c0-b6ba-34b12e85a26e"

static int testlsm_inode_init_security(struct inode *inode,
				struct inode *dir, const struct qstr *qstr,
				const char **name, void **value, size_t *len,
				struct xattr *lsm_xattrs)
{
#ifdef LSMBUG
	uuid_t ima_uuid, ima_uuid2;
#endif
	int ret = -EOPNOTSUPP;
#ifdef XATTR
	if (name)
		*name = lsm_xattrs ? XATTR_TESTLSM_SUFFIX : XATTR_NAME_TESTLSM;
#ifdef LSMBUG
	ret = uuid_parse(IMA_UUID, &ima_uuid);
	if (ret < 0)
		return ret;

	ret = uuid_parse(IMA_UUID2, &ima_uuid2);
	if (ret < 0)
		return ret;

	if (uuid_equal(&ima_uuid, &inode->i_sb->s_uuid) ||
	   !strcmp(inode->i_sb->s_type->name, "reiserfs"))
		return 0;
#endif
	if (value && len) {
		*value = kstrdup(TESTLSM_NAME, GFP_NOFS);
		if (!*value)
			return -ENOMEM;

		*len = sizeof(TESTLSM_NAME);
	}

	ret = 0;
#endif
	return ret;
}

static struct security_hook_list testlsm_hook[] __lsm_ro_after_init = {
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
};
