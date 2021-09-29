/* SPDX-License-Identifier: GPL-2.0+ */
/* PGP signature processing
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_PGP_SIG_H
#define _LINUX_PGP_SIG_H

#include <crypto/hash_info.h>
#include <linux/module_signature.h>

struct key;
struct pgp_sig_verify;

extern struct pgp_sig_verify *pgp_verify_sig_begin(struct key *keyring,
					const u8 *sigdata, size_t siglen);
extern int pgp_verify_sig_add_data(struct pgp_sig_verify *ctx,
				   const void *data, size_t datalen);
extern int pgp_get_digest(struct pgp_sig_verify *ctx, const u8 *sigdata,
			  size_t siglen, const u8 **buf, u32 *len,
			  enum hash_algo *hash_algo);
extern int pgp_verify_sig_end(struct pgp_sig_verify *ctx);
extern void pgp_verify_sig_cancel(struct pgp_sig_verify *ctx);
extern int pgp_check_sig(const struct module_signature *ms, size_t file_len,
			 const char *name);

#endif /* _LINUX_PGP_SIG_H */
