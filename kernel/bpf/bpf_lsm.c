// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>
#include <linux/kallsyms.h>
#include <linux/bpf_verifier.h>
#include <net/bpf_sk_storage.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf_ids.h>
#include <linux/ima.h>
#include <linux/verification.h>
#include <linux/module_signature.h>

/* For every LSM hook that allows attachment of BPF programs, declare a nop
 * function where a BPF program can be attached.
 */
#define LSM_HOOK(RET, DEFAULT, NAME, ...)	\
noinline RET bpf_lsm_##NAME(__VA_ARGS__)	\
{						\
	return DEFAULT;				\
}

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

#define LSM_HOOK(RET, DEFAULT, NAME, ...) BTF_ID(func, bpf_lsm_##NAME)
BTF_SET_START(bpf_lsm_hooks)
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK
BTF_SET_END(bpf_lsm_hooks)

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog)
{
	if (!prog->gpl_compatible) {
		bpf_log(vlog,
			"LSM programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	if (!btf_id_set_contains(&bpf_lsm_hooks, prog->aux->attach_btf_id)) {
		bpf_log(vlog, "attach_btf_id %u points to wrong type name %s\n",
			prog->aux->attach_btf_id, prog->aux->attach_func_name);
		return -EINVAL;
	}

	return 0;
}

/* Mask for all the currently supported BPRM option flags */
#define BPF_F_BRPM_OPTS_MASK	BPF_F_BPRM_SECUREEXEC

BPF_CALL_2(bpf_bprm_opts_set, struct linux_binprm *, bprm, u64, flags)
{
	if (flags & ~BPF_F_BRPM_OPTS_MASK)
		return -EINVAL;

	bprm->secureexec = (flags & BPF_F_BPRM_SECUREEXEC);
	return 0;
}

BTF_ID_LIST_SINGLE(bpf_bprm_opts_set_btf_ids, struct, linux_binprm)

static const struct bpf_func_proto bpf_bprm_opts_set_proto = {
	.func		= bpf_bprm_opts_set,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_bprm_opts_set_btf_ids[0],
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_ima_inode_hash, struct inode *, inode, void *, dst, u32, size)
{
	return ima_inode_hash(inode, dst, size);
}

static bool bpf_ima_inode_hash_allowed(const struct bpf_prog *prog)
{
	return bpf_lsm_is_sleepable_hook(prog->aux->attach_btf_id);
}

BTF_ID_LIST_SINGLE(bpf_ima_inode_hash_btf_ids, struct, inode)

static const struct bpf_func_proto bpf_ima_inode_hash_proto = {
	.func		= bpf_ima_inode_hash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_ima_inode_hash_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.allowed	= bpf_ima_inode_hash_allowed,
};

BPF_CALL_3(bpf_ima_file_hash, struct file *, file, void *, dst, u32, size)
{
	return ima_file_hash(file, dst, size);
}

BTF_ID_LIST_SINGLE(bpf_ima_file_hash_btf_ids, struct, file)

static const struct bpf_func_proto bpf_ima_file_hash_proto = {
	.func		= bpf_ima_file_hash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_ima_file_hash_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.allowed	= bpf_ima_inode_hash_allowed,
};

BPF_CALL_2(bpf_mod_verify_sig, const void *, mod, size_t, modlen)
{
	const size_t marker_len = strlen(MODULE_SIG_STRING);
	struct module_signature ms;
	size_t sig_len;
	u8 saved_id_type;
	int ret;

	pr_devel("==>%s(,%zu)\n", __func__, modlen);

	if (modlen <= marker_len)
		return -ENOENT;

	if (memcmp(mod + modlen - marker_len, MODULE_SIG_STRING, marker_len))
		return -ENOENT;

	modlen -= marker_len;

	if (modlen <= sizeof(ms))
		return -EBADMSG;

	memcpy(&ms, mod + (modlen - sizeof(ms)), sizeof(ms));

	saved_id_type = ms.id_type;
	ms.id_type = PKEY_ID_PKCS7;

	ret = mod_check_sig(&ms, modlen, "bpf_data");
	if (ret)
		return ret;

	sig_len = be32_to_cpu(ms.sig_len);
	modlen -= sig_len + sizeof(ms);

	switch (saved_id_type) {
	case PKEY_ID_PKCS7:
		ret = verify_pkcs7_signature(mod, modlen, mod + modlen, sig_len,
					     VERIFY_USE_SECONDARY_KEYRING,
					     VERIFYING_MODULE_SIGNATURE,
					     NULL, NULL);
		break;
	case PKEY_ID_PGP:
		ret = verify_pgp_signature(mod, modlen, mod + modlen, sig_len,
					   VERIFY_USE_SECONDARY_KEYRING,
					   VERIFYING_MODULE_SIGNATURE,
					   NULL, NULL);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return (ret < 0) ? ret : modlen;
}
EXPORT_SYMBOL_GPL(bpf_mod_verify_sig);

static const struct bpf_func_proto bpf_mod_verify_sig_proto = {
	.func		= bpf_mod_verify_sig,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.allowed	= bpf_ima_inode_hash_allowed,
};

static const struct bpf_func_proto *
bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_inode_storage_get:
		return &bpf_inode_storage_get_proto;
	case BPF_FUNC_inode_storage_delete:
		return &bpf_inode_storage_delete_proto;
#ifdef CONFIG_NET
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
#endif /* CONFIG_NET */
	case BPF_FUNC_spin_lock:
		return &bpf_spin_lock_proto;
	case BPF_FUNC_spin_unlock:
		return &bpf_spin_unlock_proto;
	case BPF_FUNC_bprm_opts_set:
		return &bpf_bprm_opts_set_proto;
	case BPF_FUNC_ima_inode_hash:
		return prog->aux->sleepable ? &bpf_ima_inode_hash_proto : NULL;
	case BPF_FUNC_ima_file_hash:
		return prog->aux->sleepable ? &bpf_ima_file_hash_proto : NULL;
	case BPF_FUNC_mod_verify_sig:
		return prog->aux->sleepable ? &bpf_mod_verify_sig_proto : NULL;
	default:
		return tracing_prog_func_proto(func_id, prog);
	}
}

/* The set of hooks which are called without pagefaults disabled and are allowed
 * to "sleep" and thus can be used for sleepable BPF programs.
 */
BTF_SET_START(sleepable_lsm_hooks)
BTF_ID(func, bpf_lsm_bpf)
BTF_ID(func, bpf_lsm_bpf_map)
BTF_ID(func, bpf_lsm_bpf_map_alloc_security)
BTF_ID(func, bpf_lsm_bpf_map_free_security)
BTF_ID(func, bpf_lsm_bpf_prog)
BTF_ID(func, bpf_lsm_bprm_check_security)
BTF_ID(func, bpf_lsm_bprm_committed_creds)
BTF_ID(func, bpf_lsm_bprm_committing_creds)
BTF_ID(func, bpf_lsm_bprm_creds_for_exec)
BTF_ID(func, bpf_lsm_bprm_creds_from_file)
BTF_ID(func, bpf_lsm_capget)
BTF_ID(func, bpf_lsm_capset)
BTF_ID(func, bpf_lsm_cred_prepare)
BTF_ID(func, bpf_lsm_file_ioctl)
BTF_ID(func, bpf_lsm_file_lock)
BTF_ID(func, bpf_lsm_file_open)
BTF_ID(func, bpf_lsm_file_receive)

#ifdef CONFIG_SECURITY_NETWORK
BTF_ID(func, bpf_lsm_inet_conn_established)
#endif /* CONFIG_SECURITY_NETWORK */

BTF_ID(func, bpf_lsm_inode_create)
BTF_ID(func, bpf_lsm_inode_free_security)
BTF_ID(func, bpf_lsm_inode_getattr)
BTF_ID(func, bpf_lsm_inode_getxattr)
BTF_ID(func, bpf_lsm_inode_mknod)
BTF_ID(func, bpf_lsm_inode_need_killpriv)
BTF_ID(func, bpf_lsm_inode_post_setxattr)
BTF_ID(func, bpf_lsm_inode_readlink)
BTF_ID(func, bpf_lsm_inode_rename)
BTF_ID(func, bpf_lsm_inode_rmdir)
BTF_ID(func, bpf_lsm_inode_setattr)
BTF_ID(func, bpf_lsm_inode_setxattr)
BTF_ID(func, bpf_lsm_inode_symlink)
BTF_ID(func, bpf_lsm_inode_unlink)
BTF_ID(func, bpf_lsm_kernel_module_request)
BTF_ID(func, bpf_lsm_kernel_read_file)
BTF_ID(func, bpf_lsm_kernfs_init_security)

#ifdef CONFIG_KEYS
BTF_ID(func, bpf_lsm_key_free)
#endif /* CONFIG_KEYS */

BTF_ID(func, bpf_lsm_mmap_file)
BTF_ID(func, bpf_lsm_netlink_send)
BTF_ID(func, bpf_lsm_path_notify)
BTF_ID(func, bpf_lsm_release_secctx)
BTF_ID(func, bpf_lsm_sb_alloc_security)
BTF_ID(func, bpf_lsm_sb_eat_lsm_opts)
BTF_ID(func, bpf_lsm_sb_kern_mount)
BTF_ID(func, bpf_lsm_sb_mount)
BTF_ID(func, bpf_lsm_sb_remount)
BTF_ID(func, bpf_lsm_sb_set_mnt_opts)
BTF_ID(func, bpf_lsm_sb_show_options)
BTF_ID(func, bpf_lsm_sb_statfs)
BTF_ID(func, bpf_lsm_sb_umount)
BTF_ID(func, bpf_lsm_settime)

#ifdef CONFIG_SECURITY_NETWORK
BTF_ID(func, bpf_lsm_socket_accept)
BTF_ID(func, bpf_lsm_socket_bind)
BTF_ID(func, bpf_lsm_socket_connect)
BTF_ID(func, bpf_lsm_socket_create)
BTF_ID(func, bpf_lsm_socket_getpeername)
BTF_ID(func, bpf_lsm_socket_getpeersec_dgram)
BTF_ID(func, bpf_lsm_socket_getsockname)
BTF_ID(func, bpf_lsm_socket_getsockopt)
BTF_ID(func, bpf_lsm_socket_listen)
BTF_ID(func, bpf_lsm_socket_post_create)
BTF_ID(func, bpf_lsm_socket_recvmsg)
BTF_ID(func, bpf_lsm_socket_sendmsg)
BTF_ID(func, bpf_lsm_socket_shutdown)
BTF_ID(func, bpf_lsm_socket_socketpair)
#endif /* CONFIG_SECURITY_NETWORK */

BTF_ID(func, bpf_lsm_syslog)
BTF_ID(func, bpf_lsm_task_alloc)
BTF_ID(func, bpf_lsm_current_getsecid_subj)
BTF_ID(func, bpf_lsm_task_getsecid_obj)
BTF_ID(func, bpf_lsm_task_prctl)
BTF_ID(func, bpf_lsm_task_setscheduler)
BTF_ID(func, bpf_lsm_task_to_inode)
BTF_SET_END(sleepable_lsm_hooks)

bool bpf_lsm_is_sleepable_hook(u32 btf_id)
{
	return btf_id_set_contains(&sleepable_lsm_hooks, btf_id);
}

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = bpf_lsm_func_proto,
	.is_valid_access = btf_ctx_access,
};
