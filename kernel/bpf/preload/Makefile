# SPDX-License-Identifier: GPL-2.0

LIBBPF_INCLUDE = $(srctree)/tools/lib

obj-$(CONFIG_BPF_PRELOAD_UMD) += bpf_preload.o
CFLAGS_bpf_preload_kern.o += -I$(LIBBPF_INCLUDE)
bpf_preload-objs += bpf_preload_kern.o

obj-$(CONFIG_BPF_DIGLIM) += diglim_kern.o
CFLAGS_diglim_kern_preload.o += -I $(LIBBPF_INCLUDE)
diglim_kern-objs += diglim_kern_preload.o
