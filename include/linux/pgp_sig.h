/* PGP signature processing
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_PGP_SIG_H
#define _LINUX_PGP_SIG_H

struct key;
struct pgp_sig_verify;

extern struct pgp_sig_verify *pgp_verify_sig_begin(struct key *keyring,
						   const u8 *sigdata, size_t siglen);
extern int pgp_verify_sig_add_data(struct pgp_sig_verify *ctx,
				   const void *data, size_t datalen);
extern int pgp_verify_sig_end(struct pgp_sig_verify *ctx,
			      const u8 *sig, size_t siglen, bool *_trusted);
extern void pgp_verify_sig_cancel(struct pgp_sig_verify *ctx);

extern __init int preload_pgp_keys(const u8 *pgpdata, size_t pgpdatalen,
				   struct key *keyring);

#endif /* _LINUX_PGP_SIG_H */
