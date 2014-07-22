/* PGP public key signature verification [RFC 4880]
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PGPSIG: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <linux/pgp_sig.h>
#include <linux/pgplib.h>
#include <linux/err.h>
#include <keys/asymmetric-type.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include "pgp_parser.h"
#include "public_key.h"

static const struct {
	enum hash_algo algo : 8;
} pgp_pubkey_hash[PGP_HASH__LAST] = {
	[PGP_HASH_MD5].algo		= HASH_ALGO_MD5,
	[PGP_HASH_SHA1].algo		= HASH_ALGO_SHA1,
	[PGP_HASH_RIPE_MD_160].algo	= HASH_ALGO_RIPE_MD_160,
	[PGP_HASH_SHA256].algo		= HASH_ALGO_SHA256,
	[PGP_HASH_SHA384].algo		= HASH_ALGO_SHA384,
	[PGP_HASH_SHA512].algo		= HASH_ALGO_SHA512,
	[PGP_HASH_SHA224].algo		= HASH_ALGO_SHA224,
};

struct pgp_sig_verify {
	struct public_key_signature sig;
	const struct public_key *pub;
	struct key *key;
	u8 signed_hash_msw[2];
	struct shash_desc hash;
};

/*
 * Find a key in the given keyring by issuer and authority.
 */
static struct key *pgp_request_asymmetric_key(struct key *keyring,
					      struct pgp_sig_parameters *params)
{
	key_ref_t key;
	char *id;

	BUG_ON(params->pubkey_algo >= PGP_PUBKEY__LAST);

	/* Construct an identifier. */
	id = kasprintf(GFP_KERNEL,
		       "public_key:%08x%08x",
		       be32_to_cpu(params->issuer32[0]),
		       be32_to_cpu(params->issuer32[1]));
	if (!id)
		return ERR_PTR(-ENOMEM);

	pr_debug("Look up key: \"%s\"\n", id);

	key = keyring_search(make_key_ref(keyring, 1),
			     &key_type_asymmetric, id);
	if (IS_ERR(key) && current_cred()->session_keyring) {
		rcu_read_lock();
		key = keyring_search(
			make_key_ref(rcu_dereference(current_cred()->session_keyring), 1),
			&key_type_asymmetric, id);

		rcu_read_unlock();
		if (IS_ERR(key))
			pr_debug("Request for public key '%s' err %ld\n",
				 id, PTR_ERR(key));
	}
	kfree(id);

	if (IS_ERR(key)) {
		switch (PTR_ERR(key)) {
			/* Hide some search errors */
		case -EACCES:
		case -ENOTDIR:
		case -EAGAIN:
			return ERR_PTR(-ENOKEY);
		default:
			return ERR_CAST(key);
		}
	}

	kleave(" = 0 [%x]", key_serial(key_ref_to_ptr(key)));
	return key_ref_to_ptr(key);
}

struct pgp_sig_parse_context {
	struct pgp_parse_context pgp;
	struct pgp_sig_parameters params;
};

static int pgp_parse_signature(struct pgp_parse_context *context,
			       enum pgp_packet_tag type,
			       u8 headerlen,
			       const u8 *data,
			       size_t datalen)
{
	struct pgp_sig_parse_context *ctx =
		container_of(context, struct pgp_sig_parse_context, pgp);

	return pgp_parse_sig_params(&data, &datalen, &ctx->params);
}

/**
 * pgp_verify_sig_begin - Begin the process of verifying a signature
 * @keyring: Ring of keys to search for the public key
 * @sigdata: Signature blob
 * @siglen: Length of signature blob
 *
 * This involves allocating the hash into which first the data and then the
 * metadata will be put, and parsing the signature to check that it matches one
 * of the keys in the supplied keyring.
 */
struct pgp_sig_verify *pgp_verify_sig_begin(struct key *keyring,
					    const u8 *sigdata, size_t siglen)
{
	struct pgp_sig_parse_context p;
	const struct public_key *pub;
	struct pgp_sig_verify *ctx;
	struct crypto_shash *tfm;
	struct key *key;
	enum pkey_algo pkey_algo_id;
	size_t digest_size, desc_size;
	int ret;

	kenter(",,%zu", siglen);

	p.pgp.types_of_interest = (1 << PGP_PKT_SIGNATURE);
	p.pgp.process_packet = pgp_parse_signature;
	ret = pgp_parse_packets(sigdata, siglen, &p.pgp);
	if (ret < 0)
		return ERR_PTR(ret);

	/* Check the signature itself for usefulness */
	if (p.params.pubkey_algo >= PGP_PUBKEY__LAST)
		goto unsupported_pkey_algo;
	pkey_algo_id = pgp_to_public_key_algo[p.params.pubkey_algo];
	if (pkey_algo_id == PKEY_ALGO__LAST)
		goto unsupported_pkey_algo;
	if (!pkey_algo[pkey_algo_id])
		goto unsupported_pkey_algo;

	if (p.params.hash_algo >= PGP_HASH__LAST ||
	    !pgp_hash_algorithms[p.params.hash_algo]) {
		pr_debug("Unsupported hash algorithm %u\n",
			 p.params.hash_algo);
		return ERR_PTR(-ENOPKG);
	}

	pr_debug("Signature generated with %s hash\n",
		 pgp_hash_algorithms[p.params.hash_algo]);

	if (p.params.signature_type != PGP_SIG_BINARY_DOCUMENT_SIG &&
	    p.params.signature_type != PGP_SIG_STANDALONE_SIG) {
		/* We don't want to canonicalise */
		kleave(" = -EOPNOTSUPP [canon]");
		return ERR_PTR(-EOPNOTSUPP);
	}

	/* Now we need to find a key to use */
	key = pgp_request_asymmetric_key(keyring, &p.params);
	if (IS_ERR(key)) {
		kleave(" = %ld [reqkey]", PTR_ERR(key));
		return ERR_CAST(key);
	}
	pub = key->payload.data;

	if (pkey_algo[pkey_algo_id] != pub->algo) {
		kleave(" = -EKEYREJECTED [wrong pk algo]");
		ret = -EKEYREJECTED;
		goto error_have_key;
	}

	if (!(pub->capabilities & PKEY_CAN_VERIFY)) {
		kleave(" = -EKEYREJECTED [key can't verify]");
		ret = -EKEYREJECTED;
		goto error_have_key;
	}

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(pgp_hash_algorithms[p.params.hash_algo], 0, 0);
	if (IS_ERR(tfm)) {
		ret = (PTR_ERR(tfm) == -ENOENT ? -ENOPKG : PTR_ERR(tfm));
		goto error_have_key;
	}

	desc_size = crypto_shash_descsize(tfm);
	digest_size = crypto_shash_digestsize(tfm);

	/* We allocate the hash operational data storage on the end of our
	 * context data.
	 */
	ctx = kzalloc(sizeof(*ctx) + desc_size + digest_size, GFP_KERNEL);
	if (!ctx) {
		ret = -ENOMEM;
		goto error_have_shash;
	}

	ctx->key		= key;
	ctx->pub		= pub;
	ctx->sig.pkey_hash_algo	= pgp_pubkey_hash[p.params.hash_algo].algo;
	ctx->sig.digest		= (u8 *)ctx + sizeof(*ctx) + desc_size;
	ctx->sig.digest_size	= digest_size;
	ctx->hash.tfm		= tfm;
	ctx->hash.flags		= CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_init(&ctx->hash);
	if (ret < 0)
		goto error_have_shash;

	kleave(" = %p", ctx);
	return ctx;

error_have_shash:
	crypto_free_shash(tfm);
error_have_key:
	key_put(key);
	return ERR_PTR(ret);

unsupported_pkey_algo:
	pr_debug("Unsupported public key algorithm %u\n",
		 p.params.pubkey_algo);
	return ERR_PTR(-ENOPKG);
}

/*
 * Load data into the hash
 */
int pgp_verify_sig_add_data(struct pgp_sig_verify *ctx,
			    const void *data, size_t datalen)
{
	return crypto_shash_update(&ctx->hash, data, datalen);
}

struct pgp_sig_digest_context {
	struct pgp_parse_context pgp;
	struct pgp_sig_verify *ctx;
};

/*
 * Extract required metadata from the signature packet and add what we need to
 * to the hash.
 */
static int pgp_digest_signature(struct pgp_parse_context *context,
				enum pgp_packet_tag type,
				u8 headerlen,
				const u8 *data,
				size_t datalen)
{
	struct pgp_sig_digest_context *pgp_ctx =
		container_of(context, struct pgp_sig_digest_context, pgp);
	struct pgp_sig_verify *ctx = pgp_ctx->ctx;
	struct public_key_signature *sig = &ctx->sig;
	enum pgp_signature_version version;
	int i;

	kenter(",%u,%u,,%zu", type, headerlen, datalen);

	version = *data;
	if (version == PGP_SIG_VERSION_3) {
		/* We just include an excerpt of the metadata from a V3
		 * signature.
		 */
		crypto_shash_update(&ctx->hash, data + 1, 5);
		data += sizeof(struct pgp_signature_v3_packet);
		datalen -= sizeof(struct pgp_signature_v3_packet);
	} else if (version == PGP_SIG_VERSION_4) {
		/* We add the whole metadata header and some of the hashed data
		 * for a V4 signature, plus a trailer.
		 */
		size_t hashedsz, unhashedsz;
		u8 trailer[6];

		hashedsz = 4 + 2 + (data[4] << 8) + data[5];
		crypto_shash_update(&ctx->hash, data, hashedsz);

		trailer[0] = version;
		trailer[1] = 0xffU;
		trailer[2] = hashedsz >> 24;
		trailer[3] = hashedsz >> 16;
		trailer[4] = hashedsz >> 8;
		trailer[5] = hashedsz;

		crypto_shash_update(&ctx->hash, trailer, 6);
		data += hashedsz;
		datalen -= hashedsz;

		unhashedsz = 2 + (data[0] << 8) + data[1];
		data += unhashedsz;
		datalen -= unhashedsz;
	}

	if (datalen <= 2) {
		kleave(" = -EBADMSG");
		return -EBADMSG;
	}

	/* There's a quick check on the hash available. */
	ctx->signed_hash_msw[0] = *data++;
	ctx->signed_hash_msw[1] = *data++;
	datalen -= 2;

	/* And then the cryptographic data, which we'll need for the
	 * algorithm.
	 */
	sig->nr_mpi = ctx->pub->algo->n_sig_mpi;
	for (i = 0; i < sig->nr_mpi; i++) {
		unsigned int remaining = datalen;
		if (remaining == 0) {
			pr_debug("short %zu mpi %d\n", datalen, i);
			return -EBADMSG;
		}
		sig->mpi[i] = mpi_read_from_buffer(data, &remaining);
		if (!sig->mpi[i])
			return -ENOMEM;
		data += remaining;
		datalen -= remaining;
	}

	if (datalen != 0) {
		kleave(" = -EBADMSG [trailer %zu]", datalen);
		return -EBADMSG;
	}

	kleave(" = 0");
	return 0;
}

/*
 * The data is now all loaded into the hash; load the metadata, finalise the
 * hash and perform the verification step.
 */
int pgp_verify_sig_end(struct pgp_sig_verify *ctx,
		       const u8 *sigdata, size_t siglen,
		       bool *_trusted)
{
	struct pgp_sig_digest_context p;
	int ret;

	kenter("");

	/* Firstly we add metadata, starting with some of the data from the
	 * signature packet */
	p.pgp.types_of_interest = (1 << PGP_PKT_SIGNATURE);
	p.pgp.process_packet = pgp_digest_signature;
	p.ctx = ctx;
	ret = pgp_parse_packets(sigdata, siglen, &p.pgp);
	if (ret < 0)
		goto error_free_ctx;

	ret = crypto_shash_final(&ctx->hash, ctx->sig.digest);
	if (ret < 0) {
		ctx->hash.tfm = NULL;
		goto error_free_ctx;
	}
	pr_debug("hash: %*phN\n", ctx->sig.digest_size, ctx->sig.digest);

	if (ctx->sig.digest[0] != ctx->signed_hash_msw[0] ||
	    ctx->sig.digest[1] != ctx->signed_hash_msw[1]) {
		pr_err("Hash (%02x%02x) mismatch against quick check (%02x%02x)\n",
		       ctx->sig.digest[0], ctx->sig.digest[1],
		       ctx->signed_hash_msw[0], ctx->signed_hash_msw[1]);
		ret = -EKEYREJECTED;
		return ret;
	}

	ret = verify_signature(ctx->key, &ctx->sig);
	if (ret == 0 && _trusted)
		*_trusted = test_bit(KEY_FLAG_TRUSTED, &ctx->key->flags);

error_free_ctx:
	pgp_verify_sig_cancel(ctx);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Cancel an in-progress data loading
 */
void pgp_verify_sig_cancel(struct pgp_sig_verify *ctx)
{
	int i;

	kenter("");

	/* !!! Do we need to tell the crypto layer to cancel too? */
	key_put(ctx->key);
	crypto_free_shash(ctx->hash.tfm);
	for (i = 0; i < ARRAY_SIZE(ctx->sig.mpi); i++)
		mpi_free(ctx->sig.mpi[i]);
	kfree(ctx);

	kleave("");
}
