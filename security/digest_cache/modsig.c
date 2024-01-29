// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2019  IBM Corporation
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Strip module-style appended signatures.
 */

#define pr_fmt(fmt) "DIGEST CACHE: "fmt
#include <linux/module.h>
#include <linux/module_signature.h>

#include "internal.h"

/**
 * digest_cache_strip_modsig - Strip module-style appended sig from digest list
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function strips the module-style appended signature from a digest list,
 * if present.
 *
 * Return: Size of stripped data on success, original size otherwise.
 */
size_t digest_cache_strip_modsig(__u8 *data, size_t data_len)
{
	const size_t marker_len = strlen(MODULE_SIG_STRING);
	const struct module_signature *sig;
	size_t parsed_data_len = data_len;
	size_t sig_len;
	const void *p;

	/* From ima_modsig.c */
	if (data_len <= marker_len + sizeof(*sig))
		return data_len;

	p = data + parsed_data_len - marker_len;
	if (memcmp(p, MODULE_SIG_STRING, marker_len))
		return data_len;

	parsed_data_len -= marker_len;
	sig = (const struct module_signature *)(p - sizeof(*sig));

	/* From module_signature.c */
	if (be32_to_cpu(sig->sig_len) >= parsed_data_len - sizeof(*sig))
		return data_len;

	/* Unlike for module signatures, accept all signature types. */
	if (sig->algo != 0 ||
	    sig->hash != 0 ||
	    sig->signer_len != 0 ||
	    sig->key_id_len != 0 ||
	    sig->__pad[0] != 0 ||
	    sig->__pad[1] != 0 ||
	    sig->__pad[2] != 0) {
		pr_debug("Signature info has unexpected non-zero params\n");
		return data_len;
	}

	sig_len = be32_to_cpu(sig->sig_len);
	parsed_data_len -= sig_len + sizeof(*sig);
	return parsed_data_len;
}
