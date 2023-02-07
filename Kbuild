# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux BPFILTER layer.
#

LIBBPF_SRCS = $(srctree)/tools/lib/bpf/
LIBBPF_A = $(obj)/libbpf.a
LIBBPF_OUT = $(abspath $(obj))

$(LIBBPF_A):
	$(Q)$(MAKE) -C $(LIBBPF_SRCS) O=$(LIBBPF_OUT)/ OUTPUT=$(LIBBPF_OUT)/ $(LIBBPF_OUT)/libbpf.a

userprogs := bpfilter_umh
bpfilter_umh-objs := main.o logger.o map-common.o
bpfilter_umh-objs += context.o codegen.o
bpfilter_umh-objs += match.o xt_udp.o target.o rule.o table.o
bpfilter_umh-objs += sockopt.o
bpfilter_umh-objs += filter-table.o
bpfilter_umh-userldlibs := $(LIBBPF_A) -lelf -lz
userccflags += -I /usr/include -I $(srctree)/tools/include/ -I $(srctree)/tools/lib -I $(srctree)/tools/include/uapi

$(obj)/bpfilter_umh: $(LIBBPF_A)

$(obj)/bpfilter_umh_blob.o: $(obj)/bpfilter_umh

obj-m += bpfilter.o
bpfilter-objs += bpfilter_kern.o bpfilter_umh_blob.o
