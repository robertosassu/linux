// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generate RPM digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <limits.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>
#include <bits/endianness.h>

#include "common.h"

#if __BYTE_ORDER == __BIG_ENDIAN
#include <linux/byteorder/big_endian.h>
#else
#include <linux/byteorder/little_endian.h>
#endif

const unsigned char rpm_header_magic[8] = {
	0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
};

/* In stripped ARM and x86-64 modules, ~ is surprisingly rare. */
#define MODULE_SIG_STRING "~Module signature appended~\n"

enum pkey_id_type {
	PKEY_ID_PGP,		/* OpenPGP generated key ID */
	PKEY_ID_X509,		/* X.509 arbitrary subjectKeyIdentifier */
	PKEY_ID_PKCS7,		/* Signature in PKCS#7 message */
};

/*
 * Module signature information block.
 *
 * The constituents of the signature section are, in order:
 *
 *	- Signer's name
 *	- Key identifier
 *	- Signature data
 *	- Information block
 */
struct module_signature {
	u8	algo;		/* Public-key crypto algorithm [0] */
	u8	hash;		/* Digest algorithm [0] */
	u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	u8	signer_len;	/* Length of signer's name [0] */
	u8	key_id_len;	/* Length of key identifier [0] */
	u8	__pad[3];
	__be32	sig_len;	/* Length of signature data */
};

static int gen_filename_prefix(char *filename, int filename_len, int pos,
			       const char *format, enum compact_types type)
{
	return snprintf(filename, filename_len, "%d-%s_list-%s-",
			(pos >= 0) ? pos : 0, compact_types_str[type], format);
}

static void gen_filename(Header rpm, int pos, enum compact_types type,
			 char *filename, int filename_len, char *output_format)
{
	rpmtd name = rpmtdNew(), version = rpmtdNew();
	rpmtd release = rpmtdNew(), arch = rpmtdNew();
	int prefix_len;

	headerGet(rpm, RPMTAG_NAME, name, 0);
	headerGet(rpm, RPMTAG_VERSION, version, 0);
	headerGet(rpm, RPMTAG_RELEASE, release, 0);
	headerGet(rpm, RPMTAG_ARCH, arch, 0);

	prefix_len = gen_filename_prefix(filename, filename_len, pos,
					 output_format, type);

	snprintf(filename + prefix_len, filename_len - prefix_len,
		 "%s-%s-%s.%s", rpmtdGetString(name), rpmtdGetString(version),
		 rpmtdGetString(release), rpmtdGetString(arch));

	rpmtdFree(name);
	rpmtdFree(version);
	rpmtdFree(release);
	rpmtdFree(arch);
}

static int find_package(Header rpm, char *package)
{
	rpmtd name = rpmtdNew();
	int found = 0;

	headerGet(rpm, RPMTAG_NAME, name, 0);
	if (!strncmp(rpmtdGetString(name), package, strlen(package)))
		found = 1;

	rpmtdFree(name);
	return found;
}

static int write_rpm_header(Header rpm, int dirfd, char *filename)
{
	rpmtd immutable;
	ssize_t ret;
	int fd;

	fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -EACCES;

	ret = write(fd, rpm_header_magic, sizeof(rpm_header_magic));
	if (ret != sizeof(rpm_header_magic)) {
		ret = -EIO;
		goto out;
	}

	immutable = rpmtdNew();
	headerGet(rpm, RPMTAG_HEADERIMMUTABLE, immutable, 0);
	ret = write(fd, immutable->data, immutable->count);
	if (ret != immutable->count) {
		ret = -EIO;
		goto out;
	}

	rpmtdFree(immutable);
out:
	close(fd);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}

static int write_rpm_header_signature(Header rpm, int dirfd, char *filename)
{
	struct module_signature modsig = { 0 };
	rpmtd signature = rpmtdNew();
	int ret, fd;

	headerGet(rpm, RPMTAG_RSAHEADER, signature, 0);
	fd = openat(dirfd, filename, O_WRONLY | O_APPEND);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	modsig.id_type = PKEY_ID_PGP;
	modsig.sig_len = signature->count;
	modsig.sig_len = __cpu_to_be32(modsig.sig_len);

	ret = write(fd, signature->data, signature->count);
	if (ret != signature->count) {
		ret = -EIO;
		goto out_fd;
	}

	ret = write(fd, &modsig, sizeof(modsig));
	if (ret != sizeof(modsig)) {
		ret = -EIO;
		goto out_fd;
	}

	ret = write(fd, MODULE_SIG_STRING, sizeof(MODULE_SIG_STRING) - 1);
	if (ret != sizeof(MODULE_SIG_STRING) - 1) {
		ret = -EIO;
		goto out;
	}

	ret = 0;
out_fd:
	close(fd);
out:
	rpmtdFree(signature);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <output directory>: directory digest lists are written to\n"
	       "\t-r <RPM path>: RPM package the digest list is generated from (all RPM packages in DB if not specified)\n"
	       "\t-p <package>: selected RPM package in RPM DB\n"
	       "\t-h: display help\n");
}

static int gen_rpm_digest_list(Header rpm, int dirfd, char *filename)
{
	int ret;

	ret = write_rpm_header(rpm, dirfd, filename);
	if (ret < 0) {
		printf("Cannot generate %s digest list\n", filename);
		return ret;
	}

	ret = write_rpm_header_signature(rpm, dirfd, filename);
	if (ret < 0)
		printf("Cannot add signature to %s digest list\n",
		       filename);

	return ret;
}

int main(int argc, char *argv[])
{
	char filename[NAME_MAX + 1];
	rpmts ts = NULL;
	Header hdr;
	FD_t fd;
	rpmdbMatchIterator mi;
	rpmVSFlags vsflags = 0;
	char *input_package = NULL, *selected_package = NULL;
	char *output_dir = NULL;
	struct stat st;
	int c;
	int ret, dirfd;

	while ((c = getopt(argc, argv, "d:r:p:h")) != -1) {
		switch (c) {
		case 'd':
			output_dir = optarg;
			break;
		case 'r':
			input_package = optarg;
			break;
		case 'p':
			selected_package = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			printf("Invalid option %c\n", c);
			exit(1);
		}
	}

	if (!output_dir) {
		printf("Output directory not specified\n");
		exit(1);
	}

	if (stat(output_dir, &st) == -1)
		mkdir(output_dir, 0755);

	dirfd = open(output_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", output_dir, -errno);
		ret = -errno;
		goto out;
	}

	ts = rpmtsCreate();
	if (!ts) {
		rpmlog(RPMLOG_NOTICE, "rpmtsCreate() error..\n");
		ret = -EACCES;
		goto out;
	}

	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		ret = -EACCES;
		goto out;
	}

	if (input_package) {
		vsflags |= _RPMVSF_NODIGESTS;
		vsflags |= _RPMVSF_NOSIGNATURES;
		rpmtsSetVSFlags(ts, vsflags);

		fd = Fopen(input_package, "r.ufdio");
		if ((!fd) || Ferror(fd)) {
			rpmlog(RPMLOG_NOTICE,
			       "Failed to open package file %s, %s\n",
			       input_package, Fstrerror(fd));
			ret = -EACCES;
			goto out_rpm;
		}

		ret = rpmReadPackageFile(ts, fd, "rpm", &hdr);
		Fclose(fd);

		if (ret != RPMRC_OK) {
			rpmlog(RPMLOG_NOTICE,
			       "Could not read package file %s\n",
			       input_package);
			goto out_rpm;
		}

		gen_filename(hdr, 0, COMPACT_FILE, filename, sizeof(filename),
			     "rpm");

		ret = gen_rpm_digest_list(hdr, dirfd, filename);
		headerFree(hdr);
		goto out_rpm;
	}

	mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
	while ((hdr = rpmdbNextIterator(mi)) != NULL) {
		gen_filename(hdr, 0, COMPACT_FILE, filename, sizeof(filename),
			     "rpm");

		if (strstr(filename, "gpg-pubkey") != NULL)
			continue;

		if (selected_package && !find_package(hdr, selected_package))
			continue;

		ret = gen_rpm_digest_list(hdr, dirfd, filename);
		if (ret < 0)
			break;
	}

	rpmdbFreeIterator(mi);
out_rpm:
	rpmFreeRpmrc();
	rpmtsFree(ts);
out:
	close(dirfd);
	return ret;
}
