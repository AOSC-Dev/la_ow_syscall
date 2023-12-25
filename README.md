la\_ow\_syscall
====

This kernel modules provides compatibility with LoongArch's old-world ABI,
making it possible to run old-world applications (such as Kingsoft's WPS Office
and Tencent QQ) transparently on new-world (ABI 2.0) kernels and userspaces.

Requirements
----

Linux Kernel >= 6.1.0 for `loongarch64` with the following option(s) set:

- `CONFIG_KALLSYMS=y` (for reading kernel symbol addresses).
- `CONFIG_KPROBES=y` (for probing kernel symbol addresses using kernels where
  base address randomisation - `CONFIG_RANDOMIZE_BASE` - is enabled).

Installation
----

You may install this kernel both as an in-tree module, an out-of-tree DKMS
dynamic module, or a version-specific module. You may pick any option that best
suits your needs.

### In-tree module

Copy this source tree as `arch/loongarch/ow_syscall` in your kernel tree and
append the following to `arch/loongarch/Kbuild`:

```
obj-y += ow_syscall/
```

After building the kernel with `make`, run the following command to build the
kernel module:

```
# $PWD is containing built objects
# /path/to/source_dir is containing Linux source code
make \
    -C /path/to/source_dir \
    ARCH=loongarch \
    O="$PWD" \
    arch/loongarch/ow_syscall/la_ow_syscall.ko \
    CONFIG_LOONGARCH_OW_SYSCALL=m
```

Upon completion, copy the kernel module in place
(`/lib/modules/.../arch/loongarch/ow_syscall/la_ow_syscall.ko`) and
re-generate modules.dep and map files:

```
depmod
```

### DKMS dynamic module

Generate a `dkms.conf`:

```
make dkms.conf
```

For installation and version management, refer to dkms(8) for details.

### Version-specific module

Build the kernel module:

```
make
```

Load the module with super user or root privilege:

```
insmod la_ow_syscall.ko
```
