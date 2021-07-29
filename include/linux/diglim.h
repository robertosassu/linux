/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * DIGLIM functions available for use by kernel subsystems.
 */

#ifndef __DIGLIM_H
#define __DIGLIM_H

#include <crypto/hash_info.h>
#include <uapi/linux/diglim.h>

#ifdef CONFIG_DIGLIM
extern int diglim_digest_get_info(u8 *digest, enum hash_algo algo,
				  enum compact_types type, u16 *modifiers,
				  u8 *actions);
#else
static inline int diglim_digest_get_info(u8 *digest, enum hash_algo algo,
					 enum compact_types type,
					 u16 *modifiers, u8 *actions)
{
	return -ENOENT;
}
#endif /*CONFIG_DIGLIM*/
#endif /*__DIGLIM_H*/
