KDIR ?= ../../../../..

MODULES = digest_cache_kern.ko

obj-m += digest_cache_kern.o

digest_cache_kern-y := kern.o ../common.o

all:
	+$(Q)$(MAKE) -C $(KDIR) M=$$PWD modules

clean:
	+$(Q)$(MAKE) -C $(KDIR) M=$$PWD clean

install: all
	+$(Q)$(MAKE) -C $(KDIR) M=$$PWD modules_install
