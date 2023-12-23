obj-m += la_ow_syscall.o fsstat.o la_ow_syscall_main.o signal.o

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
VERSION ?= $(shell cat VERSION)

default:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

install:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules_install

dkms.conf: dkms.conf.in
	m4 -DVERSION=$(VERSION) $^ > $@

dkms-add: dkms.conf
	/usr/sbin/dkms add $(CURDIR)

dkms-build: dkms.conf
	/usr/sbin/dkms build la_ow_syscall/$(VERSION)

dkms-install: dkms.conf
	/usr/sbin/dkms install la_ow_syscall/$(VERSION)

dkms-remove: dkms.conf
	/usr/sbin/dkms remove la_ow_syscall/$(VERSION) --all

modprobe-install:
	modprobe la_ow_syscall

modprobe-remove:
	modprobe -r la_ow_syscall

dev: modprobe-remove dkms-remove dkms-add dkms-build dkms-install modprobe-install
