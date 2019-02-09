# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
# Copyright (c) 2019, Intel Corporation.

#
# Makefile for the Intel(R) Ethernet Connection RDMA Linux Driver
#

ccflags-y := -I $(srctree)/drivers/net/ethernet/intel/i40e
ccflags-y += -I $(srctree)/drivers/net/ethernet/intel/ice

obj-$(CONFIG_INFINIBAND_IRDMA) += irdma.o

irdma-objs := main.o      \
             i40iw_if.o  \
             i40iw_hw.o  \
             irdma_if.o  \
             hw.o        \
             icrdma_hw.o \
             cm.o        \
             ctrl.o      \
             hmc.o       \
             pble.o      \
             puda.o      \
             uk.o        \
             utils.o     \
             verbs.o     \
             uda.o       \
             ws.o        \
             trace.o     \

CFLAGS_trace.o = -I$(src)
