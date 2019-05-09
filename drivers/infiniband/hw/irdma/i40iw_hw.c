// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2019, Intel Corporation. */

#include "osdep.h"
#include "type.h"
#include "i40iw_hw.h"
#include "status.h"
#include "protos.h"

#define I40E_CQPSQ_CQ_CQID_SHIFT 0
#define I40E_CQPSQ_CQ_CQID_MASK \
	(0xffffULL << I40E_CQPSQ_CQ_CQID_SHIFT)

static u32 i40iw_regs[IRDMA_MAX_REGS] = {
	I40E_PFPE_CQPTAIL,
	I40E_PFPE_CQPDB,
	I40E_PFPE_CCQPSTATUS,
	I40E_PFPE_CCQPHIGH,
	I40E_PFPE_CCQPLOW,
	I40E_PFPE_CQARM,
	I40E_PFPE_CQACK,
	I40E_PFPE_AEQALLOC,
	I40E_PFPE_CQPERRCODES,
	I40E_PFPE_WQEALLOC,
	I40E_PFINT_DYN_CTLN(0),
	I40IW_DB_ADDR_OFFSET,

	I40E_GLPCI_LBARCTRL,
	I40E_GLPE_CPUSTATUS0,
	I40E_GLPE_CPUSTATUS1,
	I40E_GLPE_CPUSTATUS2,
	I40E_PFINT_AEQCTL,
	I40E_PFINT_CEQCTL(0),
	I40E_VSIQF_CTL(0),
	I40E_PFHMC_PDINV,
	I40E_GLHMC_VFPDINV(0)
};

static u32 i40iw_stat_offsets_32[IRDMA_HW_STAT_INDEX_MAX_32] = {
	I40E_GLPES_PFIP4RXDISCARD(0),
	I40E_GLPES_PFIP4RXTRUNC(0),
	I40E_GLPES_PFIP4TXNOROUTE(0),
	I40E_GLPES_PFIP6RXDISCARD(0),
	I40E_GLPES_PFIP6RXTRUNC(0),
	I40E_GLPES_PFIP6TXNOROUTE(0),
	I40E_GLPES_PFTCPRTXSEG(0),
	I40E_GLPES_PFTCPRXOPTERR(0),
	I40E_GLPES_PFTCPRXPROTOERR(0),
	I40E_GLPES_PFRXVLANERR(0)
};

static u32 i40iw_stat_offsets_64[IRDMA_HW_STAT_INDEX_MAX_64] = {
	I40E_GLPES_PFIP4RXOCTSLO(0),
	I40E_GLPES_PFIP4RXPKTSLO(0),
	I40E_GLPES_PFIP4RXFRAGSLO(0),
	I40E_GLPES_PFIP4RXMCPKTSLO(0),
	I40E_GLPES_PFIP4TXOCTSLO(0),
	I40E_GLPES_PFIP4TXPKTSLO(0),
	I40E_GLPES_PFIP4TXFRAGSLO(0),
	I40E_GLPES_PFIP4TXMCPKTSLO(0),
	I40E_GLPES_PFIP6RXOCTSLO(0),
	I40E_GLPES_PFIP6RXPKTSLO(0),
	I40E_GLPES_PFIP6RXFRAGSLO(0),
	I40E_GLPES_PFIP6RXMCPKTSLO(0),
	I40E_GLPES_PFIP6TXOCTSLO(0),
	I40E_GLPES_PFIP6TXPKTSLO(0),
	I40E_GLPES_PFIP6TXFRAGSLO(0),
	I40E_GLPES_PFIP6TXMCPKTSLO(0),
	I40E_GLPES_PFTCPRXSEGSLO(0),
	I40E_GLPES_PFTCPTXSEGLO(0),
	I40E_GLPES_PFRDMARXRDSLO(0),
	I40E_GLPES_PFRDMARXSNDSLO(0),
	I40E_GLPES_PFRDMARXWRSLO(0),
	I40E_GLPES_PFRDMATXRDSLO(0),
	I40E_GLPES_PFRDMATXSNDSLO(0),
	I40E_GLPES_PFRDMATXWRSLO(0),
	I40E_GLPES_PFRDMAVBNDLO(0),
	I40E_GLPES_PFRDMAVINVLO(0),
	I40E_GLPES_PFIP4RXMCOCTSLO(0),
	I40E_GLPES_PFIP4TXMCOCTSLO(0),
	I40E_GLPES_PFIP6RXMCOCTSLO(0),
	I40E_GLPES_PFIP6TXMCOCTSLO(0),
	I40E_GLPES_PFUDPRXPKTSLO(0),
	I40E_GLPES_PFUDPTXPKTSLO(0)
};

static u64 i40iw_masks[IRDMA_MAX_MASKS] = {
	I40E_PFPE_CCQPSTATUS_CCQP_DONE_MASK,
	I40E_PFPE_CCQPSTATUS_CCQP_ERR_MASK,
	I40E_CQPSQ_STAG_PDID_MASK,
	I40E_CQPSQ_CQ_CEQID_MASK,
	I40E_CQPSQ_CQ_CQID_MASK,
};

static u64 i40iw_shifts[IRDMA_MAX_SHIFTS] = {
	I40E_PFPE_CCQPSTATUS_CCQP_DONE_SHIFT,
	I40E_PFPE_CCQPSTATUS_CCQP_ERR_SHIFT,
	I40E_CQPSQ_STAG_PDID_SHIFT,
	I40E_CQPSQ_CQ_CEQID_SHIFT,
	I40E_CQPSQ_CQ_CQID_SHIFT,
};

static struct irdma_irq_ops i40iw_irq_ops;

/**
 * i40iw_config_ceq- Configure CEQ interrupt
 * @dev: pointer to the device structure
 * @ceq_id: Completion Event Queue ID
 * @idx: vector index
 */
static void i40iw_config_ceq(struct irdma_sc_dev *dev, u32 ceq_id, u32 idx)
{
	u32 reg_val;

	reg_val = (ceq_id << I40E_PFINT_LNKLSTN_FIRSTQ_INDX_SHIFT);
	reg_val |= (QUEUE_TYPE_CEQ << I40E_PFINT_LNKLSTN_FIRSTQ_TYPE_SHIFT);
	wr32(dev->hw, I40E_PFINT_LNKLSTN(idx - 1), reg_val);

	reg_val = (0x3 << I40E_PFINT_DYN_CTLN_ITR_INDX_SHIFT);
	reg_val |= I40E_PFINT_DYN_CTLN_INTENA_MASK;
	wr32(dev->hw, I40E_PFINT_DYN_CTLN(idx - 1), reg_val);

	reg_val = (IRDMA_GLINT_CEQCTL_CAUSE_ENA_M |
		   (idx << IRDMA_GLINT_CEQCTL_MSIX_INDX_S) |
		   IRDMA_GLINT_CEQCTL_ITR_INDX_M);
	reg_val |= (NULL_QUEUE_INDEX << I40E_PFINT_CEQCTL_NEXTQ_INDX_SHIFT);

	wr32(dev->hw, dev->hw_regs[IRDMA_GLINT_CEQCTL] + 4 * ceq_id, reg_val);
}

/**
 * i40iw_ena_irq - Enable interrupt
 * @dev: pointer to the device structure
 * @idx: vector index
 */
static void i40iw_ena_irq(struct irdma_sc_dev *dev, u32 idx)
{
	u32 val;

	val = IRDMA_GLINT_DYN_CTL_INTENA_M | IRDMA_GLINT_DYN_CTL_CLEARPBA_M |
	      IRDMA_GLINT_DYN_CTL_ITR_INDX_M;
	wr32(dev->hw, dev->hw_regs[IRDMA_GLINT_DYN_CTL] + 4 * (idx - 1), val);
}

/**
 * irdma_disable_irq - Disable interrupt
 * @dev: pointer to the device structure
 * @idx: vector index
 */
static void i40iw_disable_irq(struct irdma_sc_dev *dev, u32 idx)
{
	wr32(dev->hw, dev->hw_regs[IRDMA_GLINT_DYN_CTL] + 4 * (idx - 1), 0);
}

void i40iw_init_hw(struct irdma_sc_dev *dev)
{
	int i;

	for (i = 0; i < IRDMA_MAX_REGS; ++i)
		dev->hw_regs[i] = i40iw_regs[i];

	for (i = 0; i < IRDMA_HW_STAT_INDEX_MAX_32; ++i)
		dev->hw_stats_regs_32[i] = i40iw_stat_offsets_32[i];

	for (i = 0; i < IRDMA_HW_STAT_INDEX_MAX_64; ++i)
		dev->hw_stats_regs_64[i] = i40iw_stat_offsets_64[i];

	for (i = 0; i < IRDMA_MAX_SHIFTS; ++i)
		dev->hw_shifts[i] = i40iw_shifts[i];

	for (i = 0; i < IRDMA_MAX_MASKS; ++i)
		dev->hw_masks[i] = i40iw_masks[i];

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
	dev->ceq_itr_mask_db = NULL;
	dev->aeq_itr_mask_db = NULL;

	memcpy(&i40iw_irq_ops, dev->irq_ops, sizeof(i40iw_irq_ops));
	i40iw_irq_ops.irdma_en_irq = i40iw_ena_irq;
	i40iw_irq_ops.irdma_dis_irq = i40iw_disable_irq;
	i40iw_irq_ops.irdma_cfg_ceq = i40iw_config_ceq;
	dev->irq_ops = &i40iw_irq_ops;

	/* Setup the hardware limits, hmc may limit further */
	dev->hw_attrs.uk_attrs.max_hw_wq_frags = I40IW_MAX_WQ_FRAGMENT_COUNT;
	dev->hw_attrs.uk_attrs.max_hw_read_sges = I40IW_MAX_SGE_RD;
	dev->hw_attrs.max_hw_device_pages = I40IW_MAX_PUSH_PAGE_COUNT;
	dev->hw_attrs.first_hw_vf_fpm_id = I40IW_FIRST_VF_FPM_ID;
	dev->hw_attrs.uk_attrs.max_hw_inline = I40IW_MAX_INLINE_DATA_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_push_inline = I40IW_MAX_PUSHMODE_INLINE_DATA_SIZE;
	dev->hw_attrs.max_hw_ird = I40IW_MAX_IRD_SIZE;
	dev->hw_attrs.max_hw_ord = I40IW_MAX_ORD_SIZE;
	dev->hw_attrs.max_hw_wqes = I40IW_MAX_WQ_ENTRIES;
	dev->hw_attrs.uk_attrs.max_hw_rq_quanta = I40IW_QP_SW_MAX_RQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_wq_quanta = I40IW_QP_SW_MAX_WQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_sq_chunk = I40IW_MAX_QUANTA_PER_WR;
	dev->hw_attrs.max_hw_pds = I40IW_MAX_PDS;
	dev->hw_attrs.max_stat_inst = I40IW_MAX_STATS_COUNT;
	dev->hw_attrs.max_qp_wr = I40IW_MAX_QP_WRS;
}
