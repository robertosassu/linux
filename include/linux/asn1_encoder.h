/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _LINUX_ASN1_ENCODER_H
#define _LINUX_ASN1_ENCODER_H

#include <linux/types.h>
#include <linux/asn1.h>
#ifdef __KERNEL__
#include <linux/bug.h>
#else
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)

#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	__ret_warn_on;							\
})

#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO

static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

#endif
#include <linux/asn1_ber_bytecode.h>

#define asn1_oid_len(oid) (sizeof(oid)/sizeof(u32))
unsigned char *
asn1_encode_integer(unsigned char *data, const unsigned char *end_data,
		    s64 integer);
unsigned char *
asn1_encode_oid(unsigned char *data, const unsigned char *end_data,
		u32 oid[], int oid_len);
unsigned char *
asn1_encode_tag(unsigned char *data, const unsigned char *end_data,
		u32 tag, const unsigned char *string, int len);
unsigned char *
asn1_encode_octet_string(unsigned char *data,
			 const unsigned char *end_data,
			 const unsigned char *string, u32 len);
unsigned char *
asn1_encode_sequence(unsigned char *data, const unsigned char *end_data,
		     const unsigned char *seq, int len);
unsigned char *
asn1_encode_boolean(unsigned char *data, const unsigned char *end_data,
		    bool val);

#endif
