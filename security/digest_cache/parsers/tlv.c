// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parse a tlv digest list.
 */

#define pr_fmt(fmt) "TLV DIGEST LIST: "fmt
#include <linux/tlv_parser.h>
#include <uapi/linux/tlv_digest_list.h>

#include "parsers.h"

#define kenter(FMT, ...) \
	pr_debug("==> %s(" FMT ")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_debug("<== %s()" FMT "\n", __func__, ##__VA_ARGS__)

const char *digest_list_types_str[] = {
	FOR_EACH_DIGEST_LIST_TYPE(GENERATE_STRING)
};

const char *digest_list_fields_str[] = {
	FOR_EACH_DIGEST_LIST_FIELD(GENERATE_STRING)
};

const char *digest_list_entry_types_str[] = {
	FOR_EACH_DIGEST_LIST_ENTRY_TYPE(GENERATE_STRING)
};

const char *digest_list_entry_fields_str[] = {
	FOR_EACH_DIGEST_LIST_ENTRY_FIELD(GENERATE_STRING)
};

struct tlv_callback_data {
	struct digest_cache *digest_cache;
	u64 parsed_data_type;
	u64 parsed_num_entries;
	u64 parsed_total_len;
	enum hash_algo algo;
};

/**
 * parse_digest_list_entry_digest - Parse DIGEST_LIST_ENTRY_DIGEST field
 * @tlv_data: Parser callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ENTRY_DIGEST field (file digest).
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_entry_digest(struct tlv_callback_data *tlv_data,
					  enum digest_list_entry_fields field,
					  const u8 *field_data,
					  u64 field_data_len)
{
	int ret;

	kenter(",%u,%llu", field, field_data_len);

	if (tlv_data->algo == HASH_ALGO__LAST) {
		pr_debug("Digest algo not set\n");
		ret = -EBADMSG;
		goto out;
	}

	if (field_data_len != hash_digest_size[tlv_data->algo]) {
		pr_debug("Unexpected data length %llu, expected %d\n",
			 field_data_len, hash_digest_size[tlv_data->algo]);
		ret = -EBADMSG;
		goto out;
	}

	ret = digest_cache_htable_add(tlv_data->digest_cache, (u8 *)field_data,
				      tlv_data->algo);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_entry_path - Parse DIGEST_LIST_ENTRY_PATH field
 * @tlv_data: Parser callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function handles the DIGEST_LIST_ENTRY_PATH field (file path). It
 * currently does not parse the data.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_entry_path(struct tlv_callback_data *tlv_data,
					enum digest_list_entry_fields field,
					const u8 *field_data,
					u64 field_data_len)
{
	kenter(",%u,%llu", field, field_data_len);

	kleave(" = 0");
	return 0;
}

/**
 * digest_list_entry_data_callback - DIGEST_LIST_ENTRY_DATA callback
 * @callback_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This callback handles the fields of DIGEST_LIST_ENTRY_DATA (nested) data,
 * and calls the appropriate parser.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int digest_list_entry_data_callback(void *callback_data, u64 field,
					   const u8 *field_data,
					   u64 field_data_len)
{
	struct tlv_callback_data *tlv_data;
	int ret;

	tlv_data = (struct tlv_callback_data *)callback_data;

	switch (field) {
	case DIGEST_LIST_ENTRY_DIGEST:
		ret = parse_digest_list_entry_digest(tlv_data, field,
						     field_data,
						     field_data_len);
		break;
	case DIGEST_LIST_ENTRY_PATH:
		ret = parse_digest_list_entry_path(tlv_data, field, field_data,
						   field_data_len);
		break;
	default:
		pr_debug("Unhandled field %s\n",
			 digest_list_entry_fields_str[field]);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

/**
 * parse_digest_list_algo - Parse DIGEST_LIST_ALGO field
 * @tlv_data: Parser callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ALGO field (digest algorithm).
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_algo(struct tlv_callback_data *tlv_data,
				  enum digest_list_fields field,
				  const u8 *field_data, u64 field_data_len)
{
	u64 algo;
	int ret;

	kenter(",%u,%llu", field, field_data_len);

	if (field_data_len != sizeof(u64)) {
		pr_debug("Unexpected data length %llu, expected %lu\n",
			 field_data_len, sizeof(u64));
		ret = -EBADMSG;
		goto out;
	}

	algo = __be64_to_cpu(*(u64 *)field_data);

	if (algo >= HASH_ALGO__LAST) {
		pr_debug("Unexpected digest algo %llu\n", algo);
		ret = -EBADMSG;
		goto out;
	}

	ret = digest_cache_htable_init(tlv_data->digest_cache,
				       tlv_data->parsed_num_entries, algo);
	if (ret < 0)
		goto out;

	tlv_data->algo = algo;

	pr_debug("Digest algo: %s\n", hash_algo_name[algo]);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_entry - Parse DIGEST_LIST_ENTRY field
 * @tlv_data: Parser callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ENTRY field.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_entry(struct tlv_callback_data *tlv_data,
				   enum digest_list_fields field,
				   const u8 *field_data, u64 field_data_len)
{
	int ret;

	kenter(",%u,%llu", field, field_data_len);

	ret = tlv_parse(DIGEST_LIST_ENTRY_DATA, digest_list_entry_data_callback,
			tlv_data, field_data, field_data_len,
			digest_list_entry_types_str, DIGEST_LIST_ENTRY__LAST,
			digest_list_entry_fields_str,
			DIGEST_LIST_ENTRY_FIELD__LAST);

	kleave(" = %d", ret);
	return ret;
}

/**
 * digest_list_file_callback - DIGEST_LIST_FILE callback
 * @callback_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This callback handles the fields of DIGEST_LIST_FILE data, and calls the
 * appropriate parser.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int digest_list_file_callback(void *callback_data, u64 field,
				     const u8 *field_data, u64 field_data_len)
{
	struct tlv_callback_data *tlv_data;
	int ret;

	tlv_data = (struct tlv_callback_data *)callback_data;

	switch (field) {
	case DIGEST_LIST_ALGO:
		ret = parse_digest_list_algo(tlv_data, field, field_data,
					     field_data_len);
		break;
	case DIGEST_LIST_ENTRY:
		ret = parse_digest_list_entry(tlv_data, field, field_data,
					      field_data_len);
		break;
	default:
		pr_debug("Unhandled field %s\n",
			 digest_list_fields_str[field]);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

/**
 * digest_list_parse_tlv - Parse a tlv digest list
 * @digest_cache: Digest cache
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function parses a tlv digest list.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_list_parse_tlv(struct digest_cache *digest_cache, const u8 *data,
			  size_t data_len)
{
	struct tlv_callback_data tlv_data = {
		.digest_cache = digest_cache,
		.algo = HASH_ALGO__LAST
	};
	int ret;

	ret = tlv_parse_hdr(&data, &data_len, &tlv_data.parsed_data_type,
			    &tlv_data.parsed_num_entries,
			    &tlv_data.parsed_total_len,
			    digest_list_types_str, DIGEST_LIST__LAST);
	if (ret < 0)
		return ret;

	if (tlv_data.parsed_data_type != DIGEST_LIST_FILE)
		return 0;

	return tlv_parse_data(digest_list_file_callback, &tlv_data,
			      tlv_data.parsed_num_entries, data, data_len,
			      digest_list_fields_str, DIGEST_LIST_FIELD__LAST);
}
