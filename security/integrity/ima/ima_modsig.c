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
#include <keys/asymmetric-type.h>
#include <crypto/pkcs7.h>
#include <crypto/uasym_keys_sigs.h>

#include "ima.h"

struct modsig {
	struct pkcs7_message *pkcs7_msg;
	struct uasym_sig_message *uasym_sig;
	u8 id_type;

	enum hash_algo hash_algo;

	/* This digest will go in the 'd-modsig' field of the IMA template. */
	const u8 *digest;
	u32 digest_size;

	/*
	 * This is what will go to the measurement list if the template requires
	 * storing the signature.
	 */
	int raw_sig_len;
	u8 raw_sig[] __counted_by(raw_sig_len);
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

	if (sig->id_type == PKEY_ID_PKCS7) {
		rc = mod_check_sig(sig, buf_len, func_tokens[func]);
		if (rc)
			return rc;
	} else {
		/* Same as mod_check_sig() but skipping the id_type check. */
		if (be32_to_cpu(sig->sig_len) >= buf_len - sizeof(*sig))
			return -EBADMSG;

		if (sig->algo != 0 ||
		    sig->hash != 0 ||
		    sig->signer_len != 0 ||
		    sig->key_id_len != 0 ||
		    sig->__pad[0] != 0 ||
		    sig->__pad[1] != 0 ||
		    sig->__pad[2] != 0)
			return -EBADMSG;
	}

	sig_len = be32_to_cpu(sig->sig_len);
	buf_len -= sig_len + sizeof(*sig);

	/* Allocate sig_len additional bytes to hold the raw sig data. */
	hdr = kzalloc(struct_size(hdr, raw_sig, sig_len), GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;

	hdr->raw_sig_len = sig_len;
	hdr->id_type = sig->id_type;
	if (sig->id_type == PKEY_ID_PKCS7)
		hdr->pkcs7_msg = pkcs7_parse_message(buf + buf_len, sig_len);
	else
		hdr->uasym_sig = uasym_sig_parse_message(buf + buf_len, sig_len);

	if (IS_ERR(hdr->pkcs7_msg) || IS_ERR(hdr->uasym_sig)) {
		kfree(hdr);
		return rc;
	}

	memcpy(hdr->raw_sig, buf + buf_len, sig_len);

	/* We don't know the hash algorithm yet. */
	hdr->hash_algo = HASH_ALGO__LAST;

	*modsig = hdr;

	return 0;
}

/**
 * ima_collect_modsig - Calculate the file hash without the appended signature.
 * @modsig: parsed module signature
 * @buf: data to verify the signature on
 * @size: data size
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
	if (modsig->id_type == PKEY_ID_PKCS7)
		rc = pkcs7_supply_detached_data(modsig->pkcs7_msg, buf, size);
	else
		rc = uasym_sig_supply_detached_data(modsig->uasym_sig, buf,
						    size);
	if (rc)
		return;

	/* Ask the PKCS7 code to calculate the file hash. */
	if (modsig->id_type == PKEY_ID_PKCS7)
		rc = pkcs7_get_digest(modsig->pkcs7_msg, &modsig->digest,
				      &modsig->digest_size, &modsig->hash_algo);
	else
		rc = uasym_sig_get_digest(modsig->uasym_sig, &modsig->digest,
					  &modsig->digest_size,
					  &modsig->hash_algo);
}

int ima_modsig_verify(struct key *keyring, const struct modsig *modsig)
{
	if (modsig->id_type == PKEY_ID_PKCS7)
		return verify_pkcs7_message_sig(NULL, 0, modsig->pkcs7_msg,
						keyring,
						VERIFYING_MODULE_SIGNATURE,
						NULL, NULL);
	else
		return verify_uasym_sig_message(NULL, 0, modsig->uasym_sig,
						keyring,
						VERIFYING_MODULE_SIGNATURE,
						NULL, NULL);
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

	if (modsig->id_type == PKEY_ID_PKCS7)
		pkcs7_free_message(modsig->pkcs7_msg);
	else
		uasym_sig_free_message(modsig->uasym_sig);
	kfree(modsig);
}
