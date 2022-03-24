# SPDX-License-Identifier: GPL-2.0
OUTPUT := .output
abs_out := $(abspath $(OUTPUT))

CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip

TOOLS_PATH := $(abspath ../../../../tools)
BPFTOOL_SRC := $(TOOLS_PATH)/bpf/bpftool
BPFTOOL_OUTPUT := $(abs_out)/bpftool
DEFAULT_BPFTOOL := $(OUTPUT)/sbin/bpftool
BPFTOOL ?= $(DEFAULT_BPFTOOL)

LIBBPF_SRC := $(TOOLS_PATH)/lib/bpf
LIBBPF_OUTPUT := $(abs_out)/libbpf
LIBBPF_DESTDIR := $(LIBBPF_OUTPUT)
LIBBPF_INCLUDE := $(LIBBPF_DESTDIR)/include
BPFOBJ := $(LIBBPF_OUTPUT)/libbpf.a

INCLUDES := -I$(OUTPUT) -I$(LIBBPF_INCLUDE) -I$(TOOLS_PATH)/include/uapi
CFLAGS := -g -Wall

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

.DELETE_ON_ERROR:

.PHONY: all clean

all: diglim.lskel.h diglim_kern_preload.c

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) diglim.lskel.hd diglim_kern_preload.c

diglim.lskel.h: $(OUTPUT)/diglim_kern.o $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton -L $< > $@

diglim_kern_preload.c: diglim.lskel.h $(OUTPUT)/diglim_kern.o $(BPFTOOL)
	$(call msg,GEN-PRELOAD-MOD,$@)
	$(Q)$(BPFTOOL) gen module $(OUTPUT)/diglim_kern.o diglim/$< > ../$@

$(OUTPUT)/vmlinux.h: $(OUTPUT) $(DEFAULT_BPFTOOL) ../../../../vmlinux
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file ../../../../vmlinux format c > $@

$(OUTPUT)/diglim_kern.o: diglim_kern.c $(OUTPUT)/vmlinux.h $(BPFOBJ) $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf $(INCLUDES)			      \
		 -c $(filter %.c,$^) -o $@ &&				      \
	$(LLVM_STRIP) -g $@

$(OUTPUT) $(LIBBPF_OUTPUT) $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(BPFOBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OUTPUT)
	$(Q)$(MAKE) $(submake_extras) -C $(LIBBPF_SRC)			       \
		    OUTPUT=$(abspath $(dir $@))/ prefix=		       \
		    DESTDIR=$(LIBBPF_DESTDIR) $(abspath $@) install_headers

$(DEFAULT_BPFTOOL): $(BPFOBJ) | $(BPFTOOL_OUTPUT)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOL_SRC)			       \
		    OUTPUT=$(BPFTOOL_OUTPUT)/				       \
		    LIBBPF_OUTPUT=$(LIBBPF_OUTPUT)/			       \
		    LIBBPF_DESTDIR=$(LIBBPF_DESTDIR)/			       \
		    prefix= DESTDIR=$(abs_out)/ install-bin
