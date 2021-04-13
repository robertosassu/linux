# SPDX-License-Identifier: GPL-2.0-only
CFLAGS_testlsm-xattr.o += -DTESTLSM_NAME=\"testlsm-xattr\" -DVAR_BLOB_SIZES=testlsm_xattr -DXATTR
CFLAGS_testlsm-xattr-2.o += -DTESTLSM_NAME=\"testlsm-xattr-2\" -DVAR_BLOB_SIZES=testlsm_xattr_2 -DXATTR
CFLAGS_testlsm-xattr-3.o += -DTESTLSM_NAME=\"testlsm-xattr-3\" -DVAR_BLOB_SIZES=testlsm_xattr_3 -DXATTR
CFLAGS_testlsm-xattr-bug.o += -DTESTLSM_NAME=\"testlsm-xattr-bug\" -DVAR_BLOB_SIZES=testlsm_xattr_bug -DXATTR -DLSMBUG
CFLAGS_testlsm-noxattr.o += -DTESTLSM_NAME=\"testlsm-noxattr\" -DVAR_BLOB_SIZES=testlsm_noxattr
CFLAGS_testlsm-noxattr-2.o += -DTESTLSM_NAME=\"testlsm-noxattr-2\" -DVAR_BLOB_SIZES=testlsm_noxattr_2
CFLAGS_testlsm-noxattr-3.o += -DTESTLSM_NAME=\"testlsm-noxattr-3\" -DVAR_BLOB_SIZES=testlsm_noxattr_3
CFLAGS_testlsm2-xattr.o += -DTESTLSM_NAME=\"testlsm2-xattr\" -DVAR_BLOB_SIZES=testlsm2_xattr -DXATTR -DXATTR2
CFLAGS_testlsm-xattr-disabled.o += -DTESTLSM_NAME=\"testlsm-xattr-disabled\" -DVAR_BLOB_SIZES=testlsm_xattr_disabled -DXATTR -DDISABLED_STATE

obj-$(CONFIG_SECURITY_TESTLSM) += testlsm-xattr.o testlsm-xattr-2.o \
				  testlsm-xattr-3.o testlsm-xattr-bug.o \
				  testlsm-noxattr.o testlsm-noxattr-2.o \
				  testlsm-noxattr-3.o testlsm2-xattr.o \
				  testlsm-xattr-disabled.o
