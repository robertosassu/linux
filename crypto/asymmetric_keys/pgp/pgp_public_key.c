// SPDX-License-Identifier: GPL-2.0
/* Instantiate a public key crypto key from PGP format data [RFC 4880]
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
#include <sys/socket.h>
#include <linux/keyctl.h>
#include <linux/if_alg.h>

#include "pgplib.h"

#define KEYCTL_SUPPORTS_ENCDEC \
	(KEYCTL_SUPPORTS_ENCRYPT | KEYCTL_SUPPORTS_DECRYPT)
#define KEYCTL_SUPPORTS_SIGVER (KEYCTL_SUPPORTS_SIGN | KEYCTL_SUPPORTS_VERIFY)

static const u8 oids[255][PGP_PUBKEY__LAST] = {
	[PUBKEY_ALGO_ECDSA_NIST_P256] = { 0x2A, 0x86, 0x48, 0xCE,
					  0x3D, 0x03, 0x01, 0x07 },
	[PUBKEY_ALGO_ECDSA_NIST_P384] = { 0x2B, 0x81, 0x04, 0x00, 0x22 },
};

const enum pub_key_algos pgp_to_public_key_algo[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= PUBKEY_ALGO_RSA,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= PUBKEY_ALGO_RSA,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= PUBKEY_ALGO_RSA,
	[PGP_PUBKEY_ELGAMAL]		= PUBKEY_ALGO__LAST,
	[PGP_PUBKEY_DSA]		= PUBKEY_ALGO__LAST,
	/* Select the correct curve later. */
	[PGP_PUBKEY_ECDSA]		= PUBKEY_ALGO_ECDSA,
};

static const int pgp_key_algo_p_num_mpi[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= 2,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= 2,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= 2,
	[PGP_PUBKEY_ELGAMAL]		= 3,
	[PGP_PUBKEY_DSA]		= 4,
	[PGP_PUBKEY_ECDSA]		= 1,
};

static const u8 pgp_public_key_capabilities[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= KEYCTL_SUPPORTS_ENCDEC |
					  KEYCTL_SUPPORTS_SIGVER,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= KEYCTL_SUPPORTS_ENCDEC,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= KEYCTL_SUPPORTS_SIGVER,
	[PGP_PUBKEY_ELGAMAL]		= 0,
	[PGP_PUBKEY_DSA]		= 0,
	[PGP_PUBKEY_ECDSA]		= KEYCTL_SUPPORTS_ENCDEC |
					  KEYCTL_SUPPORTS_SIGVER,
};

static inline int digest_putc(int alg_fd, uint8_t ch)
{
	return send(alg_fd, &ch, 1, MSG_MORE);
}

struct pgp_key_data_parse_context {
	struct pgp_parse_context pgp;
	struct umd_key_msg_out *out;
};

/*
 * Calculate the public key ID (RFC4880 12.2)
 */
static int pgp_calc_pkey_keyid(int alg_fd,
			       struct pgp_parse_pubkey *pgp,
			       const u8 *pub_key, size_t keylen,
			       struct umd_key_msg_out *out)
{
	unsigned int nb[MAX_MPI];
	unsigned int nn[MAX_MPI];
	unsigned int n;
	const u8 *key_ptr = pub_key;
	const u8 *pp[MAX_MPI];
	u32 a32;
	int npkey = pgp_key_algo_p_num_mpi[pgp->pubkey_algo];
	u8 oid_length = 0;
	int i, ret = 0;

	kenter("\n");

	n = (pgp->version < PGP_KEY_VERSION_4) ? 8 : 6;
	if (pgp->pubkey_algo == PGP_PUBKEY_ECDSA) {
		if (keylen < 1) {
			kleave("= -EBADMSG [not enough data]\n");
			return -EBADMSG;
		}

		oid_length = *key_ptr++;

		keylen -= 1;
		n += 1;

		if (keylen < oid_length) {
			kleave("= -EBADMSG [not enough data]\n");
			return -EBADMSG;
		}

		for (i = 0; i < PGP_PUBKEY__LAST; i++) {
			if (!memcmp(key_ptr, oids[i], oid_length)) {
				out->pkey_algo = i;
				break;
			}
		}

		if (i == PGP_PUBKEY__LAST) {
			kleave("= -EBADMSG [curve not found]\n");
			return -EBADMSG;
		}

		key_ptr += oid_length;
		keylen -= oid_length;
		n += oid_length;
	}

	for (i = 0; i < npkey; i++) {
		ret = mpi_key_length(key_ptr, keylen, nb + i, nn + i);
		if (ret < 0)
			return ret;

		if (keylen < 2 + nn[i])
			break;

		pp[i] = key_ptr + 2;
		key_ptr += 2 + nn[i];
		keylen -= 2 + nn[i];
		n += 2 + nn[i];
	}

	if (keylen != 0) {
		kleave("= -EBADMSG [excess %zu]\n", keylen);
		return -EBADMSG;
	}

	ret = digest_putc(alg_fd, 0x99);     /* ctb */
	ret |= digest_putc(alg_fd, n >> 8);   /* 16-bit header length */
	ret |= digest_putc(alg_fd, n);
	ret |= digest_putc(alg_fd, pgp->version);

	a32 = pgp->creation_time;
	ret |= digest_putc(alg_fd, a32 >> 24);
	ret |= digest_putc(alg_fd, a32 >> 16);
	ret |= digest_putc(alg_fd, a32 >>  8);
	ret |= digest_putc(alg_fd, a32 >>  0);

	if (pgp->version < PGP_KEY_VERSION_4) {
		u16 a16;

		if (pgp->expires_at)
			a16 = (pgp->expires_at - pgp->creation_time) / 86400UL;
		else
			a16 = 0;
		ret |= digest_putc(alg_fd, a16 >> 8);
		ret |= digest_putc(alg_fd, a16 >> 0);
	}

	ret |= digest_putc(alg_fd, pgp->pubkey_algo);

	for (i = 0; i < npkey; i++) {
		if (oid_length) {
			ret |= digest_putc(alg_fd, oid_length);
			ret |= send(alg_fd, oids[out->pkey_algo], oid_length,
				    MSG_MORE);
		}

		ret |= digest_putc(alg_fd, nb[i] >> 8);
		ret |= digest_putc(alg_fd, nb[i]);
		ret |= send(alg_fd, pp[i], nn[i], MSG_MORE);
	}

	kleave(" = %d\n", ret);
	return ret;
}

/*
 * Calculate the public key ID fingerprint
 */
static int pgp_generate_fingerprint(struct pgp_key_data_parse_context *ctx,
				    struct pgp_parse_pubkey *pgp,
				    const u8 *pub_key, size_t keylen,
				    struct umd_key_msg_out *out)
{
#ifdef debug
	size_t offset;
#endif
	int ret, alg_fd;

	alg_fd = pgp->version < PGP_KEY_VERSION_4 ?
		 alg_fds_array[FD_MD5] : alg_fds_array[FD_SHA1];

	ret = pgp_calc_pkey_keyid(alg_fd, pgp, pub_key, keylen, out);
	if (ret < 0)
		return ret;

	ret = recv(alg_fd, out->kids.kid1, sizeof(out->kids.kid1), 0);
	if (ret < 0)
		return ret;

	out->kids.kid1_len[0] = ret;
#ifdef debug
	offset = out->kids.kid1_len[0] - 8;
	pr_debug("offset %lu/%lu\n", offset, out->kids.kid1_len[0]);
#endif
	kleave(" = %d\n", ret);
	return ret;
}

/*
 * Extract a public key or public subkey from the PGP stream.
 */
static int pgp_process_public_key(struct pgp_parse_context *context,
				  enum pgp_packet_tag type,
				  u8 headerlen,
				  const u8 *data,
				  size_t datalen)
{
	enum pub_key_algos algo = PUBKEY_ALGO__LAST;
	struct pgp_key_data_parse_context *ctx =
		container_of(context, struct pgp_key_data_parse_context, pgp);
	struct pgp_parse_pubkey pgp;
	u8 capabilities;
	int ret;

	kenter(",%u,%u,,%zu\n", type, headerlen, datalen);

	if (ctx->out->kids.kid1_len[0]) {
		kleave(" = -ENOKEY [already]");
		return -ENOKEY;
	}

	ret = pgp_parse_public_key(&data, &datalen, &pgp);
	if (ret < 0)
		goto cleanup;

	if (pgp.pubkey_algo < PGP_PUBKEY__LAST)
		algo = pgp_to_public_key_algo[pgp.pubkey_algo];

	if (algo == PUBKEY_ALGO__LAST) {
		pr_debug("Unknown public key algorithm %u\n", pgp.pubkey_algo);
		ret = -ENOPKG;
		goto cleanup;
	}

	ctx->out->pkey_algo = algo;

	/*
	 * It's the public half of a key, so that only gives us encrypt and
	 * verify capabilities.
	 */
	capabilities = pgp_public_key_capabilities[pgp.pubkey_algo] &
		       (KEYCTL_SUPPORTS_ENCRYPT | KEYCTL_SUPPORTS_VERIFY);
	/*
	 * Capabilities are not stored anymore in the public key, store only
	 * those that allow signature verification.
	 */
	if (!(capabilities & KEYCTL_SUPPORTS_VERIFY)) {
		pr_debug("Public key algorithm %u does not support verify\n",
			 pgp.pubkey_algo);
		ret = -EOPNOTSUPP;
		goto cleanup;
	}

	ctx->out->pub_key_len = datalen;
	memcpy(ctx->out->pub_key, data, datalen);

	ret = pgp_generate_fingerprint(ctx, &pgp, data, datalen, ctx->out);
	if (ret < 0)
		goto cleanup;

	if (pgp.pubkey_algo == PGP_PUBKEY_ECDSA) {
		u8 oid_length = *data;
		unsigned int nbytes;

		if (datalen < oid_length + 1) {
			pr_debug("Not enough data for the OID\n");
			ret = -EINVAL;
			goto cleanup;
		}

		data += oid_length + 1;
		datalen -= oid_length + 1;

		ret = mpi_key_length(data, datalen, NULL, &nbytes);
		if (ret < 0) {
			pr_debug("Not enough data for the MPI\n");
			goto cleanup;
		}

		data += 2;
		datalen -= 2;

		if (datalen > sizeof(ctx->out->pub_key)) {
			pr_debug("Public key too big (%ld bytes)\n", datalen);
			ret = -EINVAL;
			goto cleanup;
		}

		memcpy(ctx->out->pub_key, data, datalen);
		ctx->out->pub_key_len = datalen;
		goto cleanup;
	}

	ret = mpi_to_asn1_integers(ctx->out->pub_key,
				ctx->out->pub_key + sizeof(ctx->out->pub_key),
				pgp_key_algo_p_num_mpi[pgp.pubkey_algo], data,
				datalen);
	if (ret < 0)
		goto cleanup;

	ctx->out->pub_key_len = ret;

	kleave(" = 0 [use]\n");
	return 0;

cleanup:
	pr_devel("cleanup\n");
	kleave(" = %d\n", ret);
	return ret;
}

void pgp_key_parse_umh(struct msg_in *in, struct msg_out *out)
{
	struct pgp_key_data_parse_context ctx;

	kenter("\n");

	memset(&ctx, 0, sizeof(ctx));
	ctx.out = &out->key;
	ctx.pgp.types_of_interest = (1 << PGP_PKT_PUBLIC_KEY);
	ctx.pgp.process_packet = pgp_process_public_key;

	out->ret = pgp_parse_packets(in->data, in->data_len, &ctx.pgp);
	kleave(" = %d\n", out->ret);
}
