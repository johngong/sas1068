ifeq ($(KVER),)
	ifeq ($(KDIR),)
		KVER = $(shell uname -r)
		KDIR := /lib/modules/$(KVER)/build
	endif
else
	KDIR := /lib/modules/$(KVER)/build
endif

export PWD    := $(shell pwd)
export LIBSAS := m

INSTALL_DIR := /lib/modules/$(shell uname -r)/extra

ifneq ($(KERNELRELEASE),)
obj-m += sas1068.o
sas1068-y += sas1068_init.o sas1068_sas.o sas1068_ctl.o sas1068_hwi.o
else
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

clean:
	rm -f *.ur-safe *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		.cache.mk Module.symvers Module.markers modules.order
	rm -rf .tmp_versions
endif
