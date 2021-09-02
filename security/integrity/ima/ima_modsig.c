// SPDX-License-Identifier: GPL-2.0+
/*
 * IMA support for appraising module-style appended signatures.
 *
 * Copyright (C) 2019  IBM Corporation
 *
 * Author:
 * Thiago Jung Bauermann <bauerman@linux.ibm.com>
 */

#include <linux/types.h>
#include <linux/module_signature.h>
#include <linux/pgp_sig.h>
#include <keys/asymmetric-type.h>
#include <crypto/pkcs7.h>

#include "ima.h"

struct modsig {
	struct pkcs7_message *pkcs7_msg;
	struct pgp_sig_verify *pgp_ctx;

	enum hash_algo hash_algo;
	enum pkey_id_type id_type;

	/* This digest will go in the 'd-modsig' field of the IMA template. */
	const u8 *digest;
	u32 digest_size;

	/*
	 * This is what will go to the measurement list if the template requires
	 * storing the signature.
	 */
	int raw_sig_len;
	u8 raw_sig[];
};

/*
 * ima_read_modsig - Read modsig from buf.
 *
 * Return: 0 on success, error code otherwise.
 */
int ima_read_modsig(enum ima_hooks func, const void *buf, loff_t buf_len,
		    struct modsig **modsig)
{
	const size_t marker_len = strlen(MODULE_SIG_STRING);
	const struct module_signature *sig;
	struct modsig *hdr;
	size_t sig_len;
	const void *p;
	int rc;

	if (buf_len <= marker_len + sizeof(*sig))
		return -ENOENT;

	p = buf + buf_len - marker_len;
	if (memcmp(p, MODULE_SIG_STRING, marker_len))
		return -ENOENT;

	buf_len -= marker_len;
	sig = (const struct module_signature *)(p - sizeof(*sig));

	switch (sig->id_type) {
	case PKEY_ID_PKCS7:
		rc = mod_check_sig(sig, buf_len, func_tokens[func]);
		break;
	case PKEY_ID_PGP:
		rc = pgp_check_sig(sig, buf_len, func_tokens[func]);
		break;
	default:
		break;
	}

	if (rc)
		return rc;

	sig_len = be32_to_cpu(sig->sig_len);
	buf_len -= sig_len + sizeof(*sig);

	/* Allocate sig_len additional bytes to hold the raw PKCS#7/PGP data. */
	hdr = kzalloc(sizeof(*hdr) + sig_len, GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;

	hdr->id_type = sig->id_type;

	switch (sig->id_type) {
	case PKEY_ID_PKCS7:
		hdr->pkcs7_msg = pkcs7_parse_message(buf + buf_len, sig_len);
		if (IS_ERR(hdr->pkcs7_msg))
			rc = PTR_ERR(hdr->pkcs7_msg);
		break;
	case PKEY_ID_PGP:
		hdr->pgp_ctx = pgp_verify_sig_begin(NULL, buf + buf_len,
						    sig_len);
		if (IS_ERR(hdr->pgp_ctx))
			rc = PTR_ERR(hdr->pgp_ctx);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	if (rc) {
		kfree(hdr);
		return rc;
	}

	memcpy(hdr->raw_sig, buf + buf_len, sig_len);
	hdr->raw_sig_len = sig_len;

	/* We don't know the hash algorithm yet. */
	hdr->hash_algo = HASH_ALGO__LAST;

	*modsig = hdr;

	return 0;
}

/**
 * ima_collect_modsig - Calculate the file hash without the appended signature.
 *
 * Since the modsig is part of the file contents, the hash used in its signature
 * isn't the same one ordinarily calculated by IMA. Therefore PKCS7 code
 * calculates a separate one for signature verification.
 */
void ima_collect_modsig(struct modsig *modsig, const void *buf, loff_t size)
{
	int rc;

	/*
	 * Provide the file contents (minus the appended sig) so that the PKCS7
	 * code can calculate the file hash.
	 */
	size -= modsig->raw_sig_len + strlen(MODULE_SIG_STRING) +
		sizeof(struct module_signature);
	switch (modsig->id_type) {
	case PKEY_ID_PKCS7:
		rc = pkcs7_supply_detached_data(modsig->pkcs7_msg, buf, size);
		break;
	case PKEY_ID_PGP:
		rc = pgp_verify_sig_add_data(modsig->pgp_ctx, buf, size);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	if (rc)
		return;

	switch (modsig->id_type) {
	case PKEY_ID_PKCS7:
		/* Ask the PKCS7 code to calculate the file hash. */
		rc = pkcs7_get_digest(modsig->pkcs7_msg, &modsig->digest,
				      &modsig->digest_size, &modsig->hash_algo);
		break;
	case PKEY_ID_PGP:
		rc = pgp_get_digest(modsig->pgp_ctx, modsig->raw_sig,
				    modsig->raw_sig_len, &modsig->digest,
				    &modsig->digest_size, &modsig->hash_algo);
		break;
	default:
		break;
	}
}

int ima_modsig_verify(struct key *keyring, const struct modsig *modsig)
{
	switch (modsig->id_type) {
	case PKEY_ID_PKCS7:
		return verify_pkcs7_message_sig(NULL, 0, modsig->pkcs7_msg,
						keyring,
						VERIFYING_MODULE_SIGNATURE,
						NULL, NULL);
	case PKEY_ID_PGP:
		return pgp_verify_sig_end(modsig->pgp_ctx);
	default:
		return -EOPNOTSUPP;
	}
}

int ima_get_modsig_digest(const struct modsig *modsig, enum hash_algo *algo,
			  const u8 **digest, u32 *digest_size)
{
	*algo = modsig->hash_algo;
	*digest = modsig->digest;
	*digest_size = modsig->digest_size;

	return 0;
}

int ima_get_raw_modsig(const struct modsig *modsig, const void **data,
		       u32 *data_len)
{
	*data = &modsig->raw_sig;
	*data_len = modsig->raw_sig_len;

	return 0;
}

void ima_free_modsig(struct modsig *modsig)
{
	if (!modsig)
		return;

	switch (modsig->id_type) {
	case PKEY_ID_PKCS7:
		pkcs7_free_message(modsig->pkcs7_msg);
		break;
	case PKEY_ID_PGP:
		pgp_verify_sig_cancel(modsig->pgp_ctx);
		break;
	default:
		break;
	}

	kfree(modsig);
}
