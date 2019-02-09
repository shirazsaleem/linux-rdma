// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2019, Intel Corporation. */

#include "osdep.h"
#include "type.h"
#include "icrdma_hw.h"

static u32 icrdma_regs[IRDMA_MAX_REGS] = {
	PFPE_CQPTAIL,
	PFPE_CQPDB,
	PFPE_CCQPSTATUS,
	PFPE_CCQPHIGH,
	PFPE_CCQPLOW,
	PFPE_CQARM,
	PFPE_CQACK,
	PFPE_AEQALLOC,
	PFPE_CQPERRCODES,
	PFPE_WQEALLOC,
	GLINT_DYN_CTL(0),
	ICRDMA_DB_ADDR_OFFSET,

	GLPCI_LBARCTRL,
	GLPE_CPUSTATUS0,
	GLPE_CPUSTATUS1,
	GLPE_CPUSTATUS2,
	PFINT_AEQCTL,
	GLINT_CEQCTL(0),
	VSIQF_PE_CTL1(0),
	PFHMC_PDINV,
	GLHMC_VFPDINV(0)
};

static u64 icrdma_masks[IRDMA_MAX_MASKS] = {
	ICRDMA_CCQPSTATUS_CCQP_DONE_M,
	ICRDMA_CCQPSTATUS_CCQP_ERR_M,
	ICRDMA_CQPSQ_STAG_PDID_M,
	ICRDMA_CQPSQ_CQ_CEQID_M,
	ICRDMA_CQPSQ_CQ_CQID_M,
};

static u64 icrdma_shifts[IRDMA_MAX_SHIFTS] = {
	ICRDMA_CCQPSTATUS_CCQP_DONE_S,
	ICRDMA_CCQPSTATUS_CCQP_ERR_S,
	ICRDMA_CQPSQ_STAG_PDID_S,
	ICRDMA_CQPSQ_CQ_CEQID_S,
	ICRDMA_CQPSQ_CQ_CQID_S,
};

void icrdma_init_hw(struct irdma_sc_dev *dev)
{
	int i;

	for (i = 0; i < IRDMA_MAX_REGS; ++i)
		dev->hw_regs[i] = icrdma_regs[i];

	for (i = 0; i < IRDMA_MAX_SHIFTS; ++i)
		dev->hw_shifts[i] = icrdma_shifts[i];

	for (i = 0; i < IRDMA_MAX_MASKS; ++i)
		dev->hw_masks[i] = icrdma_masks[i];

	dev->wqe_alloc_db = (u32 __iomem *)(irdma_get_hw_addr(dev) +
					  dev->hw_regs[IRDMA_WQEALLOC]);
	dev->cq_arm_db = (u32 __iomem *)(irdma_get_hw_addr(dev) +
				       dev->hw_regs[IRDMA_CQARM]);
	dev->aeq_alloc_db = (u32 __iomem *)(irdma_get_hw_addr(dev) +
					  dev->hw_regs[IRDMA_AEQALLOC]);
	dev->cqp_db = (u32 __iomem *)(irdma_get_hw_addr(dev) +
				    dev->hw_regs[IRDMA_CQPDB]);
	dev->cq_ack_db = (u32 __iomem *)(irdma_get_hw_addr(dev) +
				       dev->hw_regs[IRDMA_CQACK]);
	dev->hw_attrs.max_stat_inst = ICRDMA_MAX_STATS_COUNT;

	dev->hw_attrs.uk_attrs.max_hw_sq_chunk = IRDMA_MAX_QUANTA_PER_WR;
}
