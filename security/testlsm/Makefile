# SPDX-License-Identifier: GPL-2.0-only
CFLAGS_testlsm-xattr.o += -DTESTLSM_NAME=\"testlsm-xattr\" -DXATTR
CFLAGS_testlsm-xattr-2.o += -DTESTLSM_NAME=\"testlsm-xattr-2\" -DXATTR
CFLAGS_testlsm-xattr-3.o += -DTESTLSM_NAME=\"testlsm-xattr-3\" -DXATTR
CFLAGS_testlsm-xattr-bug.o += -DTESTLSM_NAME=\"testlsm-xattr-bug\" -DXATTR -DLSMBUG
CFLAGS_testlsm-noxattr.o += -DTESTLSM_NAME=\"testlsm-noxattr\"
CFLAGS_testlsm-noxattr-2.o += -DTESTLSM_NAME=\"testlsm-noxattr-2\"
CFLAGS_testlsm-noxattr-3.o += -DTESTLSM_NAME=\"testlsm-noxattr-3\"

obj-$(CONFIG_SECURITY_TESTLSM) += testlsm-xattr.o testlsm-xattr-2.o \
				  testlsm-xattr-3.o testlsm-xattr-bug.o \
				  testlsm-noxattr.o testlsm-noxattr-2.o \
				  testlsm-noxattr-3.o
