# fdwatch - loadable kernel module, built against Android DDK kernel headers.
#
#   make -C $KDIR M=$PWD ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
#
# Single source file, so `obj-m += fdwatch.o` also fixes KBUILD_MODNAME to
# "fdwatch" (the name in /proc/modules and the prefix of every message).
#
# No private kernel headers.  The three probe targets (fd_install,
# do_sys_ftruncate, vfs_write) are reached by NAME through register_kprobe(),
# which uses the kernel's own kallsyms - so there is nothing to -I into and no
# kallsyms_lookup_name() import either.

obj-m += fdwatch.o

ccflags-y += -Wno-declaration-after-statement

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
