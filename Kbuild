# SPDX-License-Identifier: GPL-2.0
#
# Makefile for LoongArch Oldworld syscall compatible layer.
#

ifdef KBUILD_EXTMOD
CONFIG_LOONGARCH_OW_SYSCALL := m
endif

obj-$(CONFIG_LOONGARCH_OW_SYSCALL) += la_ow_syscall.o
la_ow_syscall-y += fsstat.o la_ow_syscall_main.o signal.o

ifndef KBUILD_EXTMOD
  ifdef CONFIG_KALLSYMS
    ifndef CONFIG_RANDOMIZE_BASE
$(obj)/ksym_addr.h: System.map
	@$(kecho) '  GEN     $@'
	$(Q)grep ' sys_call_table$$' $< >/dev/null
	$(Q)grep ' kallsyms_lookup_name$$' $< >/dev/null
	$(Q)echo "#define LAOWSYS_SYS_CALL_TABLE_ADDR 0x$$(grep ' sys_call_table$$' $< | cut -d ' ' -f 1)" > $@
	$(Q)echo "#define LAOWSYS_KALLSYMS_LOOKUP_NAME_ADDR 0x$$(grep ' kallsyms_lookup_name$$' $< | cut -d ' ' -f 1)" >> $@
ccflags-y += -DHAVE_KSYM_ADDR
$(obj)/$(la_ow_syscall-y): $(obj)/ksym_addr.h
    endif
  endif
endif
