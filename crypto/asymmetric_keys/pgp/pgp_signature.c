// SPDX-License-Identifier: GPL-2.0-or-later
/* PGP public key signature verification [RFC 4880]
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "pgplib.h"

static const enum hash_algo pgp_hash_algorithms[PGP_HASH__LAST] = {
	[PGP_HASH_MD5]			= HASH_ALGO_MD5,
	[PGP_HASH_SHA1]			= HASH_ALGO_SHA1,
	[PGP_HASH_RIPE_MD_160]		= HASH_ALGO_RIPE_MD_160,
	[PGP_HASH_SHA256]		= HASH_ALGO_SHA256,
	[PGP_HASH_SHA384]		= HASH_ALGO_SHA384,
	[PGP_HASH_SHA512]		= HASH_ALGO_SHA512,
	[PGP_HASH_SHA224]		= HASH_ALGO_SHA224,
};

static const int pgp_sig_algo_num_mpi[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= 1,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= 1,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= 1,
	[PGP_PUBKEY_ELGAMAL]		= 2,
	[PGP_PUBKEY_DSA]		= 2,
	[PGP_PUBKEY_ECDSA]		= 2,
};

struct pgp_sig_parse_context {
	struct pgp_parse_context pgp;
	struct pgp_sig_parameters params;
	struct umd_sig_msg_out *out;
};

static int pgp_parse_signature(struct pgp_parse_context *context,
			       enum pgp_packet_tag type,
			       u8 headerlen,
			       const u8 *data,
			       size_t datalen)
{
	struct pgp_sig_parse_context *ctx =
		container_of(context, struct pgp_sig_parse_context, pgp);
	struct pgp_sig_parameters params;
	enum pgp_signature_version version;
	unsigned int nbytes, nbytes_alloc;
	enum pub_key_algos pkey_algo = PUBKEY_ALGO__LAST;
	enum hash_algo hash_algo = HASH_ALGO__LAST;
	const u8 *_data = data;
	size_t _datalen = datalen;
	int ret;

	ret = pgp_parse_sig_params(&_data, &_datalen, &params);
	if (ret < 0)
		return ret;

	if (params.signature_type != PGP_SIG_BINARY_DOCUMENT_SIG &&
	    params.signature_type != PGP_SIG_STANDALONE_SIG &&
	    params.signature_type != PGP_SIG_POSTITIVE_CERT_OF_UID_PUBKEY)
		return 0;

	/* Check the signature itself for usefulness */
	if (params.pubkey_algo < PGP_PUBKEY__LAST)
		pkey_algo = pgp_to_public_key_algo[params.pubkey_algo];

	if (pkey_algo == PUBKEY_ALGO__LAST) {
		pr_debug("Unsupported public key algorithm %u\n",
			 params.pubkey_algo);
		kleave(" = -ENOPKG [unsupp pk algo]");
		return -ENOPKG;
	}

	ctx->out->pkey_algo = pkey_algo;

	if (params.hash_algo < PGP_HASH__LAST)
		hash_algo = pgp_hash_algorithms[params.hash_algo];

	if (hash_algo == HASH_ALGO__LAST) {
		pr_debug("Unsupported hash algorithm %u\n", params.hash_algo);
		kleave(" = -ENOPKG [unsupp hash algo]");
		return -ENOPKG;
	}

	pr_debug("Signature generated with %u hash\n", hash_algo);

	ctx->out->hash_algo = hash_algo;
	ctx->out->enc = SIG_ENC_PKCS1;

	ctx->out->auth_ids.kid1_len[0] = sizeof(params.issuer.id);
	memcpy(ctx->out->auth_ids.kid1[0], params.issuer.id,
	       sizeof(params.issuer.id));

	version = *data;
	if (version == PGP_SIG_VERSION_3) {
		/* We just include an excerpt of the metadata from a V3
		 * signature.
		 */
		ctx->out->sig_data_len = 5;
		memcpy(ctx->out->sig_data, data + 2, 5);
		data += sizeof(struct pgp_signature_v3_packet);
		datalen -= sizeof(struct pgp_signature_v3_packet);
	} else if (version == PGP_SIG_VERSION_4) {
		/* We add the whole metadata header and some of the hashed data
		 * for a V4 signature, plus a trailer.
		 */
		size_t hashedsz, unhashedsz;
		u8 trailer[6];

		hashedsz = 4 + 2 + (data[4] << 8) + data[5];
		ctx->out->sig_data_len = hashedsz;
		memcpy(ctx->out->sig_data, data, hashedsz);

		trailer[0] = version;
		trailer[1] = 0xffU;
		trailer[2] = hashedsz >> 24;
		trailer[3] = hashedsz >> 16;
		trailer[4] = hashedsz >> 8;
		trailer[5] = hashedsz;

		ctx->out->sig_data_len += 6;
		memcpy(ctx->out->sig_data + hashedsz, trailer, 6);

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

	/* Skip signed_hash_msw for now. */
	data += 2;
	datalen -= 2;

	/* And then the cryptographic data, which we'll need for the
	 * algorithm.
	 */
	if (params.pubkey_algo == PGP_PUBKEY_ECDSA) {
		ret = mpi_to_asn1_integers(ctx->out->sig,
				ctx->out->sig + sizeof(ctx->out->sig),
				pgp_sig_algo_num_mpi[params.pubkey_algo], data,
				datalen);
		if (ret < 0) {
			kleave(" = -%d [ASN.1]", ret);
			return ret;
		}

		ctx->out->sig_len = ret;
		ctx->out->enc = SIG_ENC_X962;
		return 0;
	}

	ret = mpi_key_length(data, datalen, NULL, &nbytes);
	if (ret < 0) {
		kleave(" = -EBADMSG [key length]");
		return ret;
	}

	if (datalen != nbytes + 2) {
		kleave(" = -EBADMSG [size mismatch]");
		return -EBADMSG;
	}

	nbytes_alloc = DIV_ROUND_UP(nbytes, 8) * 8;
	if (nbytes_alloc > sizeof(ctx->out->sig)) {
		kleave(" = -EBADMSG [too long]");
		return -EBADMSG;
	}

	memcpy(ctx->out->sig + nbytes_alloc - nbytes, data + 2, nbytes);
	ctx->out->sig_len = nbytes_alloc;
	return 0;
}

/**
 * pgp_sig_parse_umh - Begin the process of verifying a signature
 * @in: request
 * @out: response
 *
 * This involves allocating the hash into which first the data and then the
 * metadata will be put, and parsing the signature to get the issuer ID from
 * which the key used to verify the signature will be searched.
 *
 * Return: a PGP sig context pointer on success, an error pointer on error
 */
void pgp_sig_parse_umh(struct msg_in *in, struct msg_out *out)
{
	struct pgp_sig_parse_context p;

	kenter(",,%zu\n", in->data_len);

	p.pgp.types_of_interest = (1 << PGP_PKT_SIGNATURE);
	p.pgp.process_packet = pgp_parse_signature;
	p.out = &out->sig;
	out->ret = pgp_parse_packets(in->data, in->data_len, &p.pgp);
	kleave(" = %d", out->ret);
}
