/* SPDX-License-Identifier: GPL-2.0 */
/* PGP library definitions (RFC 4880)
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <asm/bitsperlong.h>
#include "pgp.h"

extern FILE *debug_f;

#ifdef debug
#define pr_debug(...) { fprintf(debug_f, __VA_ARGS__); fflush(debug_f); }
#define pr_devel pr_debug
#define pr_info pr_debug
#define kenter pr_debug
#define kleave pr_debug
#else
#define pr_debug(...)
#define pr_devel(...)
#define pr_info(...)
#define kenter(...)
#define kleave(...)
#endif

/*
 * PGP library packet parser
 */
struct pgp_parse_context {
	u64 types_of_interest;
	int (*process_packet)(struct pgp_parse_context *context,
			      enum pgp_packet_tag type,
			      u8 headerlen,
			      const u8 *data,
			      size_t datalen);
};

extern int pgp_parse_packets(const u8 *data, size_t datalen,
			     struct pgp_parse_context *ctx);

struct pgp_parse_pubkey {
	enum pgp_key_version version : 8;
	enum pgp_pubkey_algo pubkey_algo : 8;
	__kernel_long_t creation_time;
	__kernel_long_t expires_at;
};

extern int pgp_parse_public_key(const u8 **_data, size_t *_datalen,
				struct pgp_parse_pubkey *pk);

struct pgp_parse_sig_context {
	unsigned long types_of_interest[128 / __BITS_PER_LONG];
	int (*process_packet)(struct pgp_parse_sig_context *context,
			      enum pgp_sig_subpkt_type type,
			      const u8 *data,
			      size_t datalen);
};

extern int pgp_parse_sig_packets(const u8 *data, size_t datalen,
				 struct pgp_parse_sig_context *ctx);

struct pgp_sig_parameters {
	enum pgp_signature_version version : 8;
	enum pgp_signature_type signature_type : 8;
	enum pgp_pubkey_algo pubkey_algo : 8;
	enum pgp_hash_algo hash_algo : 8;
	union {
		struct pgp_key_ID issuer;
		__be32 issuer32[2];
	};
};

extern int pgp_parse_sig_params(const u8 **_data, size_t *_datalen,
				struct pgp_sig_parameters *p);

/* From lib/mpi/mpicoder.c (in the Linux kernel). */
#define MAX_EXTERN_MPI_BITS 16384
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define MAX_MPI 5

extern int mpi_key_length(const void *xbuffer, unsigned int xbuffer_len,
			  unsigned int *nbits_arg, unsigned int *nbytes_arg);
extern int mpi_to_asn1_integers(u8 *start, u8 *end, int num_mpi, const u8 *data,
				size_t datalen);
