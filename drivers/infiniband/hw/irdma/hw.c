// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2019, Intel Corporation. */

#include "main.h"

static struct irdma_rsrc_limits rsrc_limits_table[] = {
	[0] = {
		.qplimit = 16384,
	},
	[1] = {
		.qplimit = 128,
	},
	[2] = {
		.qplimit = 1024,
	},
	[3] = {
		.qplimit = 65536,
	},
};

/* types of hmc objects */
static enum irdma_hmc_rsrc_type iw_hmc_obj_types[] = {
	IRDMA_HMC_IW_QP,
	IRDMA_HMC_IW_CQ,
	IRDMA_HMC_IW_HTE,
	IRDMA_HMC_IW_ARP,
	IRDMA_HMC_IW_APBVT_ENTRY,
	IRDMA_HMC_IW_MR,
	IRDMA_HMC_IW_XF,
	IRDMA_HMC_IW_XFFL,
	IRDMA_HMC_IW_Q1,
	IRDMA_HMC_IW_Q1FL,
	IRDMA_HMC_IW_TIMER,
	IRDMA_HMC_IW_FSIMC,
	IRDMA_HMC_IW_FSIAV,
	IRDMA_HMC_IW_RRF,
	IRDMA_HMC_IW_RRFFL,
	IRDMA_HMC_IW_HDR,
	IRDMA_HMC_IW_MD,
	IRDMA_HMC_IW_OOISC,
	IRDMA_HMC_IW_OOISCFFL,
};

/**
 * irdma_enable_intr - set up device interrupts
 * @dev: hardware control device structure
 * @msix_id: id of the interrupt to be enabled
 */
static void irdma_ena_intr(struct irdma_sc_dev *dev, u32 msix_id)
{
	dev->irq_ops->irdma_en_irq(dev, msix_id);
}

/**
 * irdma_dpc - tasklet for aeq and ceq 0
 * @data: RDMA PCI function
 */
static void irdma_dpc(unsigned long data)
{
	struct irdma_pci_f *rf = (struct irdma_pci_f *)data;

	if (rf->msix_shared)
		irdma_process_ceq(rf, rf->ceqlist);
	irdma_process_aeq(rf);
	irdma_ena_intr(&rf->sc_dev, rf->iw_msixtbl[0].idx);
}

/**
 * irdma_ceq_dpc - dpc handler for CEQ
 * @data: data points to CEQ
 */
static void irdma_ceq_dpc(unsigned long data)
{
	struct irdma_ceq *iwceq = (struct irdma_ceq *)data;
	struct irdma_pci_f *rf = iwceq->rf;

	irdma_process_ceq(rf, iwceq);
	irdma_ena_intr(&rf->sc_dev, iwceq->msix_idx);
}

/**
 * irdma_save_msix_info - copy msix vector information to iwarp device
 * @rf: RDMA PCI function
 *
 * Allocate iwdev msix table and copy the ldev msix info to the table
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code irdma_save_msix_info(struct irdma_pci_f *rf)
{
	struct irdma_priv_ldev *ldev = &rf->ldev;
	struct irdma_qvlist_info *iw_qvlist;
	struct irdma_qv_info *iw_qvinfo;
	struct msix_entry *pmsix;
	u32 ceq_idx;
	u32 i;
	u32 size;

	if (!ldev->msix_count) {
		pr_err("No MSI-X vectors for RDMA\n");
		return IRDMA_ERR_CFG;
	}

	rf->msix_count = ldev->msix_count;
	size = sizeof(struct irdma_msix_vector) * rf->msix_count;
	size += sizeof(struct irdma_qvlist_info);
	size += sizeof(struct irdma_qv_info) * rf->msix_count - 1;
	rf->iw_msixtbl = kzalloc(size, GFP_KERNEL);
	if (!rf->iw_msixtbl)
		return IRDMA_ERR_NO_MEMORY;

	rf->iw_qvlist = (struct irdma_qvlist_info *)
			(&rf->iw_msixtbl[rf->msix_count]);
	iw_qvlist = rf->iw_qvlist;
	iw_qvinfo = iw_qvlist->qv_info;
	iw_qvlist->num_vectors = rf->msix_count;
	if (rf->msix_count <= num_online_cpus())
		rf->msix_shared = true;

	for (i = 0, ceq_idx = 0, pmsix = ldev->msix_entries; i < rf->msix_count;
	     i++, iw_qvinfo++, pmsix++) {
		rf->iw_msixtbl[i].idx = pmsix->entry;
		rf->iw_msixtbl[i].irq = pmsix->vector;
		rf->iw_msixtbl[i].cpu_affinity = ceq_idx;
		if (!i) {
			iw_qvinfo->aeq_idx = 0;
			if (rf->msix_shared)
				iw_qvinfo->ceq_idx = ceq_idx++;
			else
				iw_qvinfo->ceq_idx = IRDMA_Q_INVALID_IDX;
		} else {
			iw_qvinfo->aeq_idx = IRDMA_Q_INVALID_IDX;
			iw_qvinfo->ceq_idx = ceq_idx++;
		}
		iw_qvinfo->itr_idx = 3;
		iw_qvinfo->v_idx = rf->iw_msixtbl[i].idx;
	}

	return 0;
}

/**
 * irdma_pble_initialize_lock - initialize lock for pble resource
 * @pble_rsrc: pble resource management structure pointer
 */
static void irdma_pble_initialize_lock(struct irdma_hmc_pble_rsrc *pble_rsrc)
{
		spin_lock_init(&pble_rsrc->pble_lock);
}

/**
 * irdma_irq_handler - interrupt handler for aeq and ceq0
 * @irq: Interrupt request number
 * @data: RDMA PCI function
 */
static irqreturn_t irdma_irq_handler(int irq, void *data)
{
	struct irdma_pci_f *rf = data;

	tasklet_schedule(&rf->dpc_tasklet);
	return IRQ_HANDLED;
}

/**
 * irdma_ceq_handler - interrupt handler for ceq
 * @irq: interrupt request number
 * @data: ceq pointer
 */
static irqreturn_t irdma_ceq_handler(int irq, void *data)
{
	struct irdma_ceq *iwceq = data;

	if (iwceq->irq != irq)
		dev_err(to_device(&iwceq->rf->sc_dev),
			"expected irq = %d received irq = %d\n", iwceq->irq,
			irq);
	tasklet_schedule(&iwceq->dpc_tasklet);

	return IRQ_HANDLED;
}

/**
 * irdma_destroy_irq - destroy device interrupts
 * @rf: RDMA PCI function
 * @msix_vec: msix vector to disable irq
 * @dev_id: parameter to pass to free_irq (used during irq setup)
 *
 * The function is called when destroying aeq/ceq
 */
static void irdma_destroy_irq(struct irdma_pci_f *rf,
			      struct irdma_msix_vector *msix_vec, void *dev_id)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;

	dev->irq_ops->irdma_dis_irq(dev, msix_vec->idx);
	irq_set_affinity_hint(msix_vec->irq, NULL);
	free_irq(msix_vec->irq, dev_id);
}

/**
 * irdma_destroy_cqp  - destroy control qp
 * @rf: RDMA PCI function
 * @free_hwcqp: 1 if hw cqp should be freed
 *
 * Issue destroy cqp request and
 * free the resources associated with the cqp
 */
static void irdma_destroy_cqp(struct irdma_pci_f *rf, bool free_hwcqp)
{
	enum irdma_status_code status = 0;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_cqp *cqp = &rf->cqp;

	if (free_hwcqp && dev->cqp_ops->cqp_destroy)
		status = dev->cqp_ops->cqp_destroy(dev->cqp);
	if (status)
		irdma_debug(dev, IRDMA_DEBUG_ERR, "Destroy CQP failed %d\n",
			    status);

	irdma_cleanup_pending_cqp_op(rf);
	dma_free_coherent(irdma_hw_to_dev(dev->hw), cqp->sq.size, cqp->sq.va,
			  cqp->sq.pa);
	cqp->sq.va = NULL;
	kfree(cqp->scratch_array);
	cqp->scratch_array = NULL;
	kfree(cqp->cqp_requests);
	cqp->cqp_requests = NULL;
}

/**
 * irdma_destroy_aeq - destroy aeq
 * @rf: RDMA PCI function
 *
 * Issue a destroy aeq request and
 * free the resources associated with the aeq
 * The function is called during driver unload
 */
static void irdma_destroy_aeq(struct irdma_pci_f *rf)
{
	enum irdma_status_code status = IRDMA_ERR_NOT_READY;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_aeq *aeq = &rf->aeq;

	if (!rf->msix_shared)
		irdma_destroy_irq(rf, rf->iw_msixtbl, (void *)rf);
	if (rf->reset)
		goto exit;

	if (!dev->aeq_ops->aeq_destroy(&aeq->sc_aeq, 0, 1))
		status = dev->aeq_ops->aeq_destroy_done(&aeq->sc_aeq);
	if (status)
		irdma_debug(dev, IRDMA_DEBUG_ERR, "Destroy AEQ failed %d\n",
			    status);

exit:
	dma_free_coherent(irdma_hw_to_dev(dev->hw), aeq->mem.size,
			  aeq->mem.va, aeq->mem.pa);
	aeq->mem.va = NULL;
}

/**
 * irdma_destroy_ceq - destroy ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq to be destroyed
 *
 * Issue a destroy ceq request and
 * free the resources associated with the ceq
 */
static void irdma_destroy_ceq(struct irdma_pci_f *rf, struct irdma_ceq *iwceq)
{
	enum irdma_status_code status;
	struct irdma_sc_dev *dev = &rf->sc_dev;

	if (rf->reset)
		goto exit;

	status = dev->ceq_ops->ceq_destroy(&iwceq->sc_ceq, 0, 1);
	if (status) {
		irdma_debug(dev, IRDMA_DEBUG_ERR,
			    "CEQ destroy command failed %d\n", status);
		goto exit;
	}

	status = dev->ceq_ops->cceq_destroy_done(&iwceq->sc_ceq);
	if (status)
		irdma_debug(dev, IRDMA_DEBUG_ERR,
			    "CEQ destroy completion failed %d\n", status);
exit:
	dma_free_coherent(irdma_hw_to_dev(dev->hw), iwceq->mem.size,
			  iwceq->mem.va, iwceq->mem.pa);
	iwceq->mem.va = NULL;
}

/**
 * irdma_del_ceq_0 - destroy ceq 0
 * @rf: RDMA PCI function
 *
 * Disable the ceq 0 interrupt and destroy the ceq 0
 */
static void irdma_del_ceq_0(struct irdma_pci_f *rf)
{
	struct irdma_ceq *iwceq = rf->ceqlist;
	struct irdma_msix_vector *msix_vec;

	if (rf->msix_shared) {
		msix_vec = &rf->iw_msixtbl[0];
		irdma_destroy_irq(rf, msix_vec, (void *)rf);
	} else {
		msix_vec = &rf->iw_msixtbl[1];
		irdma_destroy_irq(rf, msix_vec, (void *)iwceq);
	}
	irdma_destroy_ceq(rf, iwceq);
	rf->sc_dev.ceq_valid = false;
}

/**
 * irdma_del_ceqs - destroy all ceq's except CEQ 0 // RT mode FSL
 * @rf: RDMA PCI function
 *
 * Go through all of the device ceq's, except 0, and for each
 * ceq disable the ceq interrupt and destroy the ceq
 */
static void irdma_del_ceqs(struct irdma_pci_f *rf)
{
	struct irdma_ceq *iwceq = &rf->ceqlist[1];
	struct irdma_msix_vector *msix_vec;
	u32 i = 0;

	if (rf->msix_shared)
		msix_vec = &rf->iw_msixtbl[1];
	else
		msix_vec = &rf->iw_msixtbl[2];

	for (i = 1; i < rf->ceqs_count; i++, msix_vec++, iwceq++) {
		irdma_destroy_irq(rf, msix_vec, (void *)iwceq);
		irdma_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq,
				  IRDMA_OP_CEQ_DESTROY);
		dma_free_coherent(irdma_hw_to_dev(rf->sc_dev.hw),
				  iwceq->mem.size, iwceq->mem.va,
				  iwceq->mem.pa);
		iwceq->mem.va = NULL;
	}
}

/**
 * irdma_destroy_ccq - destroy control cq
 * @rf: RDMA PCI function
 *
 * Issue destroy ccq request and
 * free the resources associated with the ccq
 */
static void irdma_destroy_ccq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_ccq *ccq = &rf->ccq;
	enum irdma_status_code status = 0;

	if (!rf->reset)
		status = dev->ccq_ops->ccq_destroy(dev->ccq, 0, true);
	if (status)
		irdma_debug(dev, IRDMA_DEBUG_ERR, "CCQ destroy failed %d\n",
			    status);
	dma_free_coherent(irdma_hw_to_dev(dev->hw), ccq->mem_cq.size,
			  ccq->mem_cq.va, ccq->mem_cq.pa);
	ccq->mem_cq.va = NULL;
}

/**
 * irdma_close_hmc_objects_type - delete hmc objects of a given type
 * @dev: iwarp device
 * @obj_type: the hmc object type to be deleted
 * @hmc_info: host memory info struct
 * @is_pf: true if the function is PF otherwise false
 * @reset: true if called before reset
 */
static void irdma_close_hmc_objects_type(struct irdma_sc_dev *dev,
					 enum irdma_hmc_rsrc_type obj_type,
					 struct irdma_hmc_info *hmc_info,
					 bool is_pf, bool reset)
{
	struct irdma_hmc_del_obj_info info = {};

	info.hmc_info = hmc_info;
	info.rsrc_type = obj_type;
	info.count = hmc_info->hmc_obj[obj_type].cnt;
	info.is_pf = is_pf;
	if (dev->hmc_ops->del_hmc_object(dev, &info, reset))
		irdma_debug(dev, IRDMA_DEBUG_ERR,
			    "del HMC obj of type %d failed\n", obj_type);
}

/**
 * irdma_del_hmc_objects - remove all device hmc objects
 * @dev: iwarp device
 * @hmc_info: hmc_info to free
 * @is_pf: true if hmc_info belongs to PF, not vf nor allocated
 *	   by PF on behalf of VF
 * @reset: true if called before reset
 * @vers: hardware version
 */
static void irdma_del_hmc_objects(struct irdma_sc_dev *dev,
				  struct irdma_hmc_info *hmc_info, bool is_pf,
				  bool reset, enum irdma_vers vers)
{
	unsigned int i;

	for (i = 0; i < IW_HMC_OBJ_TYPE_NUM; i++) {
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt)
			irdma_close_hmc_objects_type(dev, iw_hmc_obj_types[i],
						     hmc_info, is_pf, reset);
		if (vers == IRDMA_GEN_1 && i == IRDMA_HMC_IW_TIMER)
			break;
	}
}

/**
 * irdma_create_hmc_obj_type - create hmc object of a given type
 * @dev: hardware control device structure
 * @info: information for the hmc object to create
 */
static enum irdma_status_code
irdma_create_hmc_obj_type(struct irdma_sc_dev *dev,
			  struct irdma_hmc_create_obj_info *info)
{
	return dev->hmc_ops->create_hmc_object(dev, info);
}

/**
 * irdma_create_hmc_objs - create all hmc objects for the device
 * @rf: RDMA PCI function
 * @is_pf: true if the function is PF otherwise false
 * @vers: HW version
 *
 * Create the device hmc objects and allocate hmc pages
 * Return 0 if successful, otherwise clean up and return error
 */
static enum irdma_status_code
irdma_create_hmc_objs(struct irdma_pci_f *rf, bool is_pf, enum irdma_vers vers)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_hmc_create_obj_info info = {};
	enum irdma_status_code status = 0;
	int i;

	info.hmc_info = dev->hmc_info;
	info.is_pf = is_pf;
	info.entry_type = rf->sd_type;

	for (i = 0; i < IW_HMC_OBJ_TYPE_NUM; i++) {
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt) {
			info.rsrc_type = iw_hmc_obj_types[i];
			info.count = dev->hmc_info->hmc_obj[info.rsrc_type].cnt;
			info.add_sd_cnt = 0;
			status = irdma_create_hmc_obj_type(dev, &info);
			if (status) {
				irdma_debug(dev, IRDMA_DEBUG_ERR,
					    "create obj type %d status = %d\n",
					    iw_hmc_obj_types[i], status);
				break;
			}
		}
		if (vers == IRDMA_GEN_1 && i == IRDMA_HMC_IW_TIMER)
			break;
	}

	if (!status)
		return dev->hmc_ops->static_hmc_pages_allocated(dev->cqp, 0,
								dev->hmc_fn_id,
								true, true);

	while (i) {
		i--;
		/* destroy the hmc objects of a given type */
		irdma_close_hmc_objects_type(dev, iw_hmc_obj_types[i],
					     dev->hmc_info, is_pf, false);
	}

	return status;
}

/**
 * irdma_obj_aligned_mem - get aligned memory from device allocated memory
 * @rf: RDMA PCI function
 * @memptr: points to the memory addresses
 * @size: size of memory needed
 * @mask: mask for the aligned memory
 *
 * Get aligned memory of the requested size and
 * update the memptr to point to the new aligned memory
 * Return 0 if successful, otherwise return no memory error
 */
static enum irdma_status_code
irdma_obj_aligned_mem(struct irdma_pci_f *rf, struct irdma_dma_mem *memptr,
		      u32 size, u32 mask)
{
	unsigned long va, newva;
	unsigned long extra;

	va = (unsigned long)rf->obj_next.va;
	newva = va;
	if (mask)
		newva = ALIGN(va, ((unsigned long)mask + 1ULL));
	extra = newva - va;
	memptr->va = (u8 *)va + extra;
	memptr->pa = rf->obj_next.pa + extra;
	memptr->size = size;
	if ((memptr->va + size) > (rf->obj_mem.va + rf->obj_mem.size))
		return IRDMA_ERR_NO_MEMORY;

	rf->obj_next.va = memptr->va + size;
	rf->obj_next.pa = memptr->pa + size;

	return 0;
}

/**
 * irdma_create_cqp - create control qp
 * @rf: RDMA PCI function
 *
 * Return 0, if the cqp and all the resources associated with it
 * are successfully created, otherwise return error
 */
static enum irdma_status_code irdma_create_cqp(struct irdma_pci_f *rf)
{
	enum irdma_status_code status;
	u32 sqsize = IRDMA_CQP_SW_SQSIZE_2048;
	struct irdma_dma_mem mem;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_cqp_init_info cqp_init_info = {};
	struct irdma_cqp *cqp = &rf->cqp;
	u16 maj_err, min_err;
	int i;

	cqp->cqp_requests = kcalloc(sqsize, sizeof(*cqp->cqp_requests), GFP_KERNEL);
	if (!cqp->cqp_requests)
		return IRDMA_ERR_NO_MEMORY;

	cqp->scratch_array = kcalloc(sqsize, sizeof(*cqp->scratch_array), GFP_KERNEL);
	if (!cqp->scratch_array) {
		kfree(cqp->cqp_requests);
		return IRDMA_ERR_NO_MEMORY;
	}

	dev->cqp = &cqp->sc_cqp;
	dev->cqp->dev = dev;
	cqp->sq.size = ALIGN(sizeof(struct irdma_cqp_sq_wqe) * sqsize,
			     IRDMA_CQP_ALIGNMENT);
	cqp->sq.va = dma_alloc_coherent(irdma_hw_to_dev(dev->hw),
					cqp->sq.size, &cqp->sq.pa, GFP_KERNEL);
	if (!cqp->sq.va) {
		kfree(cqp->scratch_array);
		kfree(cqp->cqp_requests);
		return IRDMA_ERR_NO_MEMORY;
	}

	status = irdma_obj_aligned_mem(rf, &mem, sizeof(struct irdma_cqp_ctx),
				       IRDMA_HOST_CTX_ALIGNMENT_M);
	if (status)
		goto exit;

	dev->cqp->host_ctx_pa = mem.pa;
	dev->cqp->host_ctx = mem.va;
	/* populate the cqp init info */
	cqp_init_info.dev = dev;
	cqp_init_info.sq_size = sqsize;
	cqp_init_info.sq = cqp->sq.va;
	cqp_init_info.sq_pa = cqp->sq.pa;
	cqp_init_info.host_ctx_pa = mem.pa;
	cqp_init_info.host_ctx = mem.va;
	cqp_init_info.hmc_profile = rf->rsrc_profile;
	cqp_init_info.ena_vf_count = rf->max_rdma_vfs;
	cqp_init_info.scratch_array = cqp->scratch_array;
	cqp_init_info.protocol_used = rf->protocol_used;
	status = dev->cqp_ops->cqp_init(dev->cqp, &cqp_init_info);
	if (status) {
		irdma_debug(dev, IRDMA_DEBUG_ERR, "cqp init status %d\n",
			    status);
		goto exit;
	}

	status = dev->cqp_ops->cqp_create(dev->cqp, &maj_err, &min_err);
	if (status) {
		irdma_debug(dev, IRDMA_DEBUG_ERR,
			    "cqp create failed - status %d maj_err %d min_err %d\n",
			    status, maj_err, min_err);
		goto exit;
	}

	spin_lock_init(&cqp->req_lock);
	spin_lock_init(&cqp->compl_lock);
	INIT_LIST_HEAD(&cqp->cqp_avail_reqs);
	INIT_LIST_HEAD(&cqp->cqp_pending_reqs);
	sema_init(&cqp->cqp_compl_sem, 0);

	/* init the waitqueue of the cqp_requests and add them to the list */
	for (i = 0; i < sqsize; i++) {
		init_waitqueue_head(&cqp->cqp_requests[i].waitq);
		list_add_tail(&cqp->cqp_requests[i].list, &cqp->cqp_avail_reqs);
	}
	init_waitqueue_head(&cqp->remove_wq);
	return 0;

exit:
	irdma_destroy_cqp(rf, false);

	return status;
}

/**
 * irdma_create_ccq - create control cq
 * @rf: RDMA PCI function
 *
 * Return 0, if the ccq and the resources associated with it
 * are successfully created, otherwise return error
 */
static enum irdma_status_code irdma_create_ccq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	enum irdma_status_code status;
	struct irdma_ccq_init_info info = {};
	struct irdma_ccq *ccq = &rf->ccq;

	dev->ccq = &ccq->sc_cq;
	dev->ccq->dev = dev;
	info.dev = dev;
	ccq->shadow_area.size = sizeof(struct irdma_cq_shadow_area);
	ccq->mem_cq.size = ALIGN(sizeof(struct irdma_cqe) * IW_CCQ_SIZE,
				 IRDMA_CQ0_ALIGNMENT);
	ccq->mem_cq.va = dma_alloc_coherent(irdma_hw_to_dev(dev->hw),
					    ccq->mem_cq.size, &ccq->mem_cq.pa,
					    GFP_KERNEL);
	if (!ccq->mem_cq.va)
		return IRDMA_ERR_NO_MEMORY;

	status = irdma_obj_aligned_mem(rf, &ccq->shadow_area,
				       ccq->shadow_area.size,
				       IRDMA_SHADOWAREA_M);
	if (status)
		goto exit;

	ccq->sc_cq.back_cq = (void *)ccq;
	/* populate the ccq init info */
	info.cq_base = ccq->mem_cq.va;
	info.cq_pa = ccq->mem_cq.pa;
	info.num_elem = IW_CCQ_SIZE;
	info.shadow_area = ccq->shadow_area.va;
	info.shadow_area_pa = ccq->shadow_area.pa;
	info.ceqe_mask = false;
	info.ceq_id_valid = true;
	info.shadow_read_threshold = 16;
	info.vsi = &rf->default_vsi;
	status = dev->ccq_ops->ccq_init(dev->ccq, &info);
	if (!status)
		status = dev->ccq_ops->ccq_create(dev->ccq, 0, true, true);
exit:
	if (status) {
		dma_free_coherent(irdma_hw_to_dev(dev->hw), ccq->mem_cq.size,
				  ccq->mem_cq.va, ccq->mem_cq.pa);
		ccq->mem_cq.va = NULL;
	}

	return status;
}

/**
 * irdma_alloc_set_mac - set up a mac address table entry
 * @iwdev: device
 *
 * Allocate a mac ip entry and add it to the hw table Return 0
 * if successful, otherwise return error
 */
static enum irdma_status_code irdma_alloc_set_mac(struct irdma_device *iwdev)
{
	enum irdma_status_code status;

	status = irdma_alloc_local_mac_entry(iwdev->rf,
					     &iwdev->mac_ip_table_idx);
	if (!status) {
		status = irdma_add_local_mac_entry(iwdev->rf,
						   (u8 *)iwdev->netdev->dev_addr,
						   (u8)iwdev->mac_ip_table_idx);
		if (status)
			irdma_del_local_mac_entry(iwdev->rf,
						  (u8)iwdev->mac_ip_table_idx);
	}
	return status;
}

/**
 * irdma_configure_ceq_vector - set up the msix interrupt vector for ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq associated with the vector
 * @ceq_id: the id number of the iwceq
 * @msix_vec: interrupt vector information
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code
irdma_cfg_ceq_vector(struct irdma_pci_f *rf, struct irdma_ceq *iwceq,
		     u32 ceq_id, struct irdma_msix_vector *msix_vec)
{
	int status;

	if (rf->msix_shared && !ceq_id) {
		tasklet_init(&rf->dpc_tasklet, irdma_dpc, (unsigned long)rf);
		status = request_irq(msix_vec->irq, irdma_irq_handler, 0,
				     "AEQCEQ", rf);
	} else {
		tasklet_init(&iwceq->dpc_tasklet, irdma_ceq_dpc,
			     (unsigned long)iwceq);

		status = request_irq(msix_vec->irq, irdma_ceq_handler, 0, "CEQ",
				     iwceq);
	}

	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_set_affinity_hint(msix_vec->irq, &msix_vec->mask);
	if (status) {
		irdma_debug(&rf->sc_dev, IRDMA_DEBUG_ERR,
			    "ceq irq config fail\n");
		return IRDMA_ERR_CFG;
	}

	msix_vec->ceq_id = ceq_id;
	rf->sc_dev.irq_ops->irdma_cfg_ceq(&rf->sc_dev, ceq_id, msix_vec->idx);

	return 0;
}

/**
 * irdma_configure_aeq_vector - set up the msix vector for aeq
 * @rf: RDMA PCI function
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code irdma_cfg_aeq_vector(struct irdma_pci_f *rf)
{
	struct irdma_msix_vector *msix_vec = rf->iw_msixtbl;
	u32 ret = 0;

	if (!rf->msix_shared) {
		tasklet_init(&rf->dpc_tasklet, irdma_dpc, (unsigned long)rf);
		ret = request_irq(msix_vec->irq, irdma_irq_handler, 0, "irdma",
				  rf);
	}
	if (ret) {
		irdma_debug(&rf->sc_dev, IRDMA_DEBUG_ERR,
			    "aeq irq config fail\n");
		return IRDMA_ERR_CFG;
	}

	rf->sc_dev.irq_ops->irdma_cfg_aeq(&rf->sc_dev, msix_vec->idx);

	return 0;
}

/**
 * irdma_create_ceq - create completion event queue
 * @rf: RDMA PCI function
 * @iwceq: pointer to the ceq resources to be created
 * @ceq_id: the id number of the iwceq
 * @vsi: SC vsi struct
 *
 * Return 0, if the ceq and the resources associated with it
 * are successfully created, otherwise return error
 */
static enum irdma_status_code irdma_create_ceq(struct irdma_pci_f *rf,
					       struct irdma_ceq *iwceq,
					       u32 ceq_id,
					       struct irdma_sc_vsi *vsi)
{
	enum irdma_status_code status;
	struct irdma_ceq_init_info info = {};
	struct irdma_sc_dev *dev = &rf->sc_dev;
	u64 scratch;

	info.ceq_id = ceq_id;
	iwceq->rf = rf;
	iwceq->mem.size = ALIGN(sizeof(struct irdma_ceqe) * rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt,
				IRDMA_CEQ_ALIGNMENT);
	iwceq->mem.va = dma_alloc_coherent(irdma_hw_to_dev(dev->hw),
					   iwceq->mem.size, &iwceq->mem.pa,
					   GFP_KERNEL);
	if (!iwceq->mem.va)
		return IRDMA_ERR_NO_MEMORY;

	info.ceq_id = ceq_id;
	info.ceqe_base = iwceq->mem.va;
	info.ceqe_pa = iwceq->mem.pa;
	info.elem_cnt = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt;
	iwceq->sc_ceq.ceq_id = ceq_id;
	info.dev = dev;
	info.vsi = vsi;
	scratch = (uintptr_t)&rf->cqp.sc_cqp;
	status = dev->ceq_ops->ceq_init(&iwceq->sc_ceq, &info);
	if (!status) {
		if (dev->ceq_valid)
			status = irdma_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq,
						   IRDMA_OP_CEQ_CREATE);
		else
			status = dev->ceq_ops->cceq_create(&iwceq->sc_ceq,
							   scratch);
	}

	if (status) {
		dma_free_coherent(irdma_hw_to_dev(dev->hw), iwceq->mem.size,
				  iwceq->mem.va, iwceq->mem.pa);
		iwceq->mem.va = NULL;
	}

	return status;
}

/**
 * irdma_setup_ceq_0 - create CEQ 0 and it's interrupt resource
 * @rf: RDMA PCI function
 *
 * Allocate a list for all device completion event queues
 * Create the ceq 0 and configure it's msix interrupt vector
 * Return 0, if successfully set up, otherwise return error
 */
static enum irdma_status_code irdma_setup_ceq_0(struct irdma_pci_f *rf)
{
	u32 i;
	struct irdma_ceq *iwceq;
	struct irdma_msix_vector *msix_vec;
	enum irdma_status_code status = 0;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.hmc_fpm_misc.max_ceqs);
	rf->ceqlist = kcalloc(num_ceqs, sizeof(*rf->ceqlist), GFP_KERNEL);
	if (!rf->ceqlist) {
		status = IRDMA_ERR_NO_MEMORY;
		goto exit;
	}

	i = (rf->msix_shared) ? 0 : 1;
	iwceq = &rf->ceqlist[0];
	status = irdma_create_ceq(rf, iwceq, 0, &rf->default_vsi);
	if (status) {
		irdma_debug(&rf->sc_dev, IRDMA_DEBUG_ERR,
			    "create ceq status = %d\n", status);
		goto exit;
	}

	msix_vec = &rf->iw_msixtbl[i];
	iwceq->irq = msix_vec->irq;
	iwceq->msix_idx = msix_vec->idx;
	status = irdma_cfg_ceq_vector(rf, iwceq, 0, msix_vec);
	if (status) {
		irdma_destroy_ceq(rf, iwceq);
		goto exit;
	}

	irdma_ena_intr(&rf->sc_dev, msix_vec->idx);
	rf->ceqs_count++;

exit:
	if (status && !rf->ceqs_count) {
		kfree(rf->ceqlist);
		rf->ceqlist = NULL;
		return status;
	}
	rf->sc_dev.ceq_valid = true;

	return 0;
}

/**
 * irdma_setup_ceqs - manage the device ceq's and their interrupt resources
 * @rf: RDMA PCI function
 * @vsi: VSI structure for this CEQ
 *
 * Allocate a list for all device completion event queues
 * Create the ceq's and configure their msix interrupt vectors
 * Return 0, if at least one ceq is successfully set up, otherwise return error
 */
static enum irdma_status_code irdma_setup_ceqs(struct irdma_pci_f *rf,
					       struct irdma_sc_vsi *vsi)
{
	u32 i;
	u32 ceq_id;
	struct irdma_ceq *iwceq;
	struct irdma_msix_vector *msix_vec;
	enum irdma_status_code status = 0;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.hmc_fpm_misc.max_ceqs);
	i = (rf->msix_shared) ? 1 : 2;
	for (ceq_id = 1; i < num_ceqs; i++, ceq_id++) {
		iwceq = &rf->ceqlist[ceq_id];
		status = irdma_create_ceq(rf, iwceq, ceq_id, vsi);
		if (status) {
			irdma_debug(&rf->sc_dev, IRDMA_DEBUG_ERR,
				    "create ceq status = %d\n", status);
			break;
		}
		msix_vec = &rf->iw_msixtbl[i];
		iwceq->irq = msix_vec->irq;
		iwceq->msix_idx = msix_vec->idx;
		status = irdma_cfg_ceq_vector(rf, iwceq, ceq_id, msix_vec);
		if (status) {
			irdma_destroy_ceq(rf, iwceq);
			break;
		}
		irdma_ena_intr(&rf->sc_dev, msix_vec->idx);
		rf->ceqs_count++;
	}

	return status;
}

/**
 * irdma_create_aeq - create async event queue
 * @rf: RDMA PCI function
 *
 * Return 0, if the aeq and the resources associated with it
 * are successfully created, otherwise return error
 */
static enum irdma_status_code irdma_create_aeq(struct irdma_pci_f *rf)
{
	enum irdma_status_code status;
	struct irdma_aeq_init_info info = {};
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_aeq *aeq = &rf->aeq;
	struct irdma_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	u64 scratch = 0;
	u32 aeq_size;

	aeq_size = 2 * hmc_info->hmc_obj[IRDMA_HMC_IW_QP].cnt +
		   hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt;
	aeq->mem.size = ALIGN(sizeof(struct irdma_sc_aeqe) * aeq_size,
			      IRDMA_AEQ_ALIGNMENT);
	aeq->mem.va = dma_alloc_coherent(irdma_hw_to_dev(dev->hw),
					 aeq->mem.size, &aeq->mem.pa,
					 GFP_KERNEL);
	if (!aeq->mem.va)
		return IRDMA_ERR_NO_MEMORY;

	info.aeqe_base = aeq->mem.va;
	info.aeq_elem_pa = aeq->mem.pa;
	info.elem_cnt = aeq_size;
	info.dev = dev;
	status = dev->aeq_ops->aeq_init(&aeq->sc_aeq, &info);
	if (status)
		goto exit;

	status = dev->aeq_ops->aeq_create(&aeq->sc_aeq, scratch, 1);
	if (!status)
		status = dev->aeq_ops->aeq_create_done(&aeq->sc_aeq);
exit:
	if (status) {
		dma_free_coherent(irdma_hw_to_dev(dev->hw), aeq->mem.size,
				  aeq->mem.va, aeq->mem.pa);
		aeq->mem.va = NULL;
	}

	return status;
}

/**
 * irdma_setup_aeq - set up the device aeq
 * @rf: RDMA PCI function
 *
 * Create the aeq and configure its msix interrupt vector
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code irdma_setup_aeq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	enum irdma_status_code status;

	status = irdma_create_aeq(rf);
	if (status)
		return status;

	status = irdma_cfg_aeq_vector(rf);
	if (status) {
		irdma_destroy_aeq(rf);
		return status;
	}

	if (!rf->msix_shared)
		irdma_ena_intr(dev, rf->iw_msixtbl[0].idx);

	return 0;
}

/**
 * irdma_initialize_ilq - create iwarp local queue for cm
 * @iwdev: iwarp device
 *
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code irdma_initialize_ilq(struct irdma_device *iwdev)
{
	struct irdma_puda_rsrc_info info = {};
	enum irdma_status_code status;

	info.type = IRDMA_PUDA_RSRC_TYPE_ILQ;
	info.cq_id = 1;
	info.qp_id = 1;
	info.count = 1;
	info.pd_id = 1;
	info.sq_size = min(iwdev->rf->max_qp / 2, (u32)32768);
	info.rq_size = info.sq_size;
	info.buf_size = 1024;
	info.tx_buf_cnt = 2 * info.sq_size;
	info.receive = irdma_receive_ilq;
	info.xmit_complete = irdma_free_sqbuf;
	status = irdma_puda_create_rsrc(&iwdev->vsi, &info);
	if (status)
		irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_ERR,
			    "ilq create fail\n");

	return status;
}

/**
 * irdma_initialize_ieq - create iwarp exception queue
 * @iwdev: iwarp device
 *
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code irdma_initialize_ieq(struct irdma_device *iwdev)
{
	struct irdma_puda_rsrc_info info = {};
	enum irdma_status_code status;

	info.type = IRDMA_PUDA_RSRC_TYPE_IEQ;
	info.cq_id = 2;
	info.qp_id = iwdev->vsi.exception_lan_q;
	info.count = 1;
	info.pd_id = 2;
	info.sq_size = min(iwdev->rf->max_qp / 2, (u32)32768);
	info.rq_size = info.sq_size;
	info.buf_size = iwdev->vsi.mtu + IRDMA_IPV4_PAD;
	info.tx_buf_cnt = 4096;
	status = irdma_puda_create_rsrc(&iwdev->vsi, &info);
	if (status)
		irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_ERR,
			    "ieq create fail\n");

	return status;
}

/**
 * irdma_reinitialize_ieq - destroy and re-create ieq
 * @vsi: VSI structure
 */
void irdma_reinitialize_ieq(struct irdma_sc_vsi *vsi)
{
	struct irdma_device *iwdev = vsi->back_vsi;

	irdma_puda_dele_rsrc(vsi, IRDMA_PUDA_RSRC_TYPE_IEQ, false);
	if (irdma_initialize_ieq(iwdev)) {
		iwdev->reset = true;
		irdma_request_reset(iwdev->rf);
	}
}

/**
 * irdma_hmc_setup - create hmc objects for the device
 * @rf: RDMA PCI function
 *
 * Set up the device private memory space for the number and size of
 * the hmc objects and create the objects
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code irdma_hmc_setup(struct irdma_pci_f *rf)
{
	enum irdma_status_code status;

	rf->sd_type = IRDMA_SD_TYPE_DIRECT;
	status = irdma_cfg_fpm_val(&rf->sc_dev,
				   rsrc_limits_table[rf->limits_sel].qplimit);
	if (status)
		return status;

	status = irdma_create_hmc_objs(rf, true, rf->rdma_ver);

	return status;
}

/**
 * irdma_del_init_mem - deallocate memory resources
 * @rf: RDMA PCI function
 */
static void irdma_del_init_mem(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;

	kfree(dev->hmc_info->sd_table.sd_entry);
	dev->hmc_info->sd_table.sd_entry = NULL;
	kfree(rf->mem_rsrc);
	rf->mem_rsrc = NULL;
	dma_free_coherent(irdma_hw_to_dev(&rf->hw), rf->obj_mem.size,
			  rf->obj_mem.va, rf->obj_mem.pa);
	rf->obj_mem.va = NULL;
	if (rf->rdma_ver != IRDMA_GEN_1) {
		kfree(rf->allocated_ws_nodes);
		rf->allocated_ws_nodes = NULL;
	}
	kfree(rf->ceqlist);
	rf->ceqlist = NULL;
	kfree(rf->iw_msixtbl);
	rf->iw_msixtbl = NULL;
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;
}

/**
 * irdma_initialize_dev - initialize device
 * @rf: RDMA PCI function
 * @ldev: lan device information
 *
 * Allocate memory for the hmc objects and initialize iwdev
 * Return 0 if successful, otherwise clean up the resources
 * and return error
 */
static enum irdma_status_code irdma_initialize_dev(struct irdma_pci_f *rf,
						   struct irdma_priv_ldev *ldev)
{
	enum irdma_status_code status;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_device_init_info info = {};
	struct irdma_dma_mem mem;
	u32 size;

	size = sizeof(struct irdma_hmc_pble_rsrc) +
	       sizeof(struct irdma_hmc_info) +
	       (sizeof(struct irdma_hmc_obj_info) * IRDMA_HMC_IW_MAX);

	rf->hmc_info_mem = kzalloc(size, GFP_KERNEL);
	if (!rf->hmc_info_mem)
		return IRDMA_ERR_NO_MEMORY;

	rf->pble_rsrc = (struct irdma_hmc_pble_rsrc *)rf->hmc_info_mem;
	dev->hmc_info = &rf->hw.hmc;
	dev->hmc_info->hmc_obj = (struct irdma_hmc_obj_info *)
				 (rf->pble_rsrc + 1);

	status = irdma_obj_aligned_mem(rf, &mem, IRDMA_QUERY_FPM_BUF_SIZE,
				       IRDMA_FPM_QUERY_BUF_ALIGNMENT_M);
	if (status)
		goto error;

	info.fpm_query_buf_pa = mem.pa;
	info.fpm_query_buf = mem.va;
	info.init_hw = rf->init_hw;

	status = irdma_obj_aligned_mem(rf, &mem, IRDMA_COMMIT_FPM_BUF_SIZE,
				       IRDMA_FPM_COMMIT_BUF_ALIGNMENT_M);
	if (status)
		goto error;

	info.fpm_commit_buf_pa = mem.pa;
	info.fpm_commit_buf = mem.va;

	info.bar0 = rf->hw.hw_addr;
	info.hmc_fn_id = (u8)ldev->fn_num;
	info.is_pf = !ldev->ftype;
	info.hw = &rf->hw;
#ifndef CONFIG_DYNAMIC_DEBUG
	if (rf->debug)
		info.debug_mask = rf->debug;
#endif
	info.vchnl_send = NULL;
	status = irdma_sc_ctrl_init(rf->rdma_ver, &rf->sc_dev, &info);
	if (status)
		goto error;

	return status;
error:
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;

	return status;
}

/**
 * irdma_deinit_rt_device - clean up the device resources
 * @iwdev: iwarp device
 *
 * Destroy the ib device interface, remove the mac ip entry and
 * ipv4/ipv6 addresses, destroy the device queues and free the
 * pble and the hmc objects
 */
void irdma_deinit_rt_device(struct irdma_device *iwdev)
{
	dev_info(to_device(&iwdev->rf->sc_dev), "state = %d\n",
		 iwdev->init_state);

	switch (iwdev->init_state) {
	case RDMA_DEV_REGISTERED:
		iwdev->iw_status = 0;
		irdma_port_ibevent(iwdev);
		irdma_destroy_rdma_device(iwdev->iwibdev);
		/* fallthrough */
	case IP_ADDR_REGISTERED:
		if (iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
			irdma_del_local_mac_entry(iwdev->rf,
						  (u8)iwdev->mac_ip_table_idx);
		/* fallthrough */
	case PBLE_CHUNK_MEM:
		/* fallthrough */
	case CEQS_CREATED:
		/* fallthrough */
	case IEQ_CREATED:
		irdma_puda_dele_rsrc(&iwdev->vsi, IRDMA_PUDA_RSRC_TYPE_IEQ,
				     iwdev->reset);
		/* fallthrough */
	case ILQ_CREATED:
		if (iwdev->create_ilq)
			irdma_puda_dele_rsrc(&iwdev->vsi,
					     IRDMA_PUDA_RSRC_TYPE_ILQ,
					     iwdev->reset);
		break;
	default:
		dev_warn(to_device(&iwdev->rf->sc_dev),
			 "bad init_state = %d\n", iwdev->init_state);
		break;
	}

	irdma_cleanup_cm_core(&iwdev->cm_core);
	if (iwdev->vsi.pestat) {
		irdma_vsi_stats_free(&iwdev->vsi);
		kfree(iwdev->vsi.pestat);
	}
}

/**
 * irdma_setup_init_state - set up the initial device struct
 * @rf: RDMA PCI function
 *
 * Initialize the iwarp device and its hdl information
 * using the ldev and client information
 * Return 0 if successful, otherwise return error
 */
static enum irdma_status_code irdma_setup_init_state(struct irdma_pci_f *rf)
{
	struct irdma_priv_ldev *ldev = &rf->ldev;
	enum irdma_status_code status;

	status = irdma_save_msix_info(rf);
	if (status)
		return status;

	rf->hw.pdev = rf->pdev;
	rf->obj_mem.size = ALIGN(8192, IRDMA_HW_PAGE_SIZE);
	rf->obj_mem.va = dma_alloc_coherent(irdma_hw_to_dev(&rf->hw),
					    rf->obj_mem.size, &rf->obj_mem.pa,
					    GFP_KERNEL);
	if (!rf->obj_mem.va) {
		kfree(rf->iw_msixtbl);
		rf->iw_msixtbl = NULL;
		return IRDMA_ERR_NO_MEMORY;
	}

	rf->obj_next = rf->obj_mem;
	rf->ooo = false;
	init_waitqueue_head(&rf->vchnl_waitq);

	status = irdma_initialize_dev(rf, ldev);
	if (status) {
		kfree(rf->iw_msixtbl);
		dma_free_coherent(irdma_hw_to_dev(&rf->hw), rf->obj_mem.size,
				  rf->obj_mem.va, rf->obj_mem.pa);
		rf->obj_mem.va = NULL;
		rf->iw_msixtbl = NULL;
	}

	return status;
}

/**
 * irdma_get_used_rsrc - determine resources used internally
 * @iwdev: iwarp device
 *
 * Called at the end of open to get all internal allocations
 */
static void irdma_get_used_rsrc(struct irdma_device *iwdev)
{
	iwdev->rf->used_pds = find_next_zero_bit(iwdev->rf->allocated_pds,
						 iwdev->rf->max_pd, 0);
	iwdev->rf->used_qps = find_next_zero_bit(iwdev->rf->allocated_qps,
						 iwdev->rf->max_qp, 0);
	iwdev->rf->used_cqs = find_next_zero_bit(iwdev->rf->allocated_cqs,
						 iwdev->rf->max_cq, 0);
	iwdev->rf->used_mrs = find_next_zero_bit(iwdev->rf->allocated_mrs,
						 iwdev->rf->max_mr, 0);
}

/**
 * irdma_deinit_hw - De-initializes RDMA HW
 * @rf: RDMA device information
 *
 */
void irdma_deinit_ctrl_hw(struct irdma_pci_f *rf)
{
	enum init_completion_state state = rf->init_state;

	rf->init_state = INVALID_STATE;
	if (rf->rsrc_created) {
		irdma_destroy_pble_prm(rf->pble_rsrc);
		irdma_del_ceqs(rf);
	}
	switch (state) {
	case CEQ0_CREATED:
		irdma_del_ceq_0(rf);
		/* fallthrough */
	case AEQ_CREATED:
		irdma_destroy_aeq(rf);
		/* fallthrough */
	case CCQ_CREATED:
		irdma_destroy_ccq(rf);
		/* fallthrough */
	case HMC_OBJS_CREATED:
		irdma_del_hmc_objects(&rf->sc_dev, rf->sc_dev.hmc_info, true,
				      rf->reset, rf->rdma_ver);
		/* fallthrough */
	case CQP_CREATED:
		if (rf->cqp.cqp_compl_thread) {
			rf->stop_cqp_thread = true;
			up(&rf->cqp.cqp_compl_sem);
			kthread_stop(rf->cqp.cqp_compl_thread);
		}
		irdma_destroy_cqp(rf, true);
		/* fallthrough */
	case INITIAL_STATE:
		irdma_del_init_mem(rf);
		break;
	case INVALID_STATE:
		/* fallthrough */
	default:
		pr_warn("bad init_state = %d\n", rf->init_state);
		break;
	}
}

enum irdma_status_code irdma_rt_init_hw(struct irdma_pci_f *rf,
					struct irdma_device *iwdev,
					struct irdma_l2params *l2params)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	enum irdma_status_code status;
	struct irdma_vsi_init_info vsi_info = {};
	struct irdma_vsi_stats_info stats_info = {};

	irdma_sc_rt_init(dev);
	vsi_info.vm_vf_type = dev->is_pf ? IRDMA_PF_TYPE : IRDMA_VF_TYPE;
	vsi_info.dev = dev;
	vsi_info.back_vsi = (void *)iwdev;
	vsi_info.params = l2params;
	vsi_info.pf_data_vsi_num = iwdev->vsi_num;
	vsi_info.exception_lan_q = 2;
	irdma_sc_vsi_init(&iwdev->vsi, &vsi_info);

	status = irdma_setup_cm_core(iwdev, rf->rdma_ver);
	if (status)
		return status;

	stats_info.pestat = kzalloc(sizeof(*stats_info.pestat), GFP_KERNEL);
	if (!stats_info.pestat) {
		return IRDMA_ERR_NO_MEMORY;
	}
	stats_info.fcn_id = dev->hmc_fn_id;
	status = irdma_vsi_stats_init(&iwdev->vsi, &stats_info);
	if (status) {
		kfree(stats_info.pestat);
		return status;
	}

	do {
		if (iwdev->create_ilq) {
			status = irdma_initialize_ilq(iwdev);
			if (status)
				break;
			iwdev->init_state = ILQ_CREATED;
		}
		status = irdma_initialize_ieq(iwdev);
		if (status)
			break;
		iwdev->init_state = IEQ_CREATED;
		if (!rf->rsrc_created) {
			status = irdma_setup_ceqs(rf, &iwdev->vsi);
			if (status)
				break;
			iwdev->init_state = CEQS_CREATED;

			iwdev->device_cap_flags = IB_DEVICE_LOCAL_DMA_LKEY |
						  IB_DEVICE_MEM_WINDOW |
						  IB_DEVICE_MEM_MGT_EXTENSIONS;

			status = irdma_hmc_init_pble(&rf->sc_dev,
						     rf->pble_rsrc);
			if (status) {
				irdma_del_ceqs(rf);
				break;
			}
			irdma_pble_initialize_lock(rf->pble_rsrc);
			iwdev->init_state = PBLE_CHUNK_MEM;
			rf->rsrc_created = true;
		}
		if (iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
			irdma_alloc_set_mac(iwdev);
		irdma_add_ip(iwdev);
		iwdev->init_state = IP_ADDR_REGISTERED;
		status = irdma_register_rdma_device(iwdev);
		if (status)
			break;
		iwdev->init_state = RDMA_DEV_REGISTERED;
		irdma_port_ibevent(iwdev);
		iwdev->iw_status = 1;
		irdma_get_used_rsrc(iwdev);
		init_waitqueue_head(&iwdev->suspend_wq);

		return 0;
	} while (0);

	dev_err(to_device(dev), "VSI open FAIL status = %d last cmpl = %d\n",
		status, iwdev->init_state);
	irdma_deinit_rt_device(iwdev);

	return status;
}

/**
 * irdma_ctrl_init_hw - Initializes RDMA HW
 * @rf: RDMA PCI function
 *
 */
enum irdma_status_code irdma_ctrl_init_hw(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	enum irdma_status_code status;

	do {
		status = irdma_setup_init_state(rf);
		if (status)
			break;
		rf->init_state = INITIAL_STATE;

		status = irdma_create_cqp(rf);
		if (status)
			break;
		rf->init_state = CQP_CREATED;

		status = irdma_hmc_setup(rf);
		if (status)
			break;
		rf->init_state = HMC_OBJS_CREATED;

		status = irdma_initialize_hw_rsrc(rf);
		if (status)
			break;

		status = irdma_create_ccq(rf);
		if (status)
			break;
		rf->init_state = CCQ_CREATED;

		status = irdma_setup_aeq(rf);
		if (status)
			break;
		rf->init_state = AEQ_CREATED;
		rf->sc_dev.feature_info[IRDMA_FEATURE_FW_INFO] = IRDMA_FW_VER_DEFAULT;

		if (rf->rdma_ver != IRDMA_GEN_1)
			status = irdma_get_rdma_features(&rf->sc_dev);
		if (!status) {
			u32 fw_ver = dev->feature_info[IRDMA_FEATURE_FW_INFO];
			u8 hw_rev = dev->hw_attrs.uk_attrs.hw_rev;

			if ((hw_rev == IRDMA_GEN_1 && fw_ver >= IRDMA_FW_VER_0x30010) ||
			    (hw_rev != IRDMA_GEN_1 && fw_ver >= IRDMA_FW_VER_0x1000D))

				dev->hw_attrs.uk_attrs.feature_flags |= IRDMA_FEATURE_RTS_AE |
									IRDMA_FEATURE_CQ_RESIZE;
		}
		rf->cqp.cqp_compl_thread =
			kthread_run(cqp_compl_thread, rf, "cqp_compl_thread");

		status = irdma_setup_ceq_0(rf);
		if (status)
			break;
		rf->init_state = CEQ0_CREATED;

		rf->free_qp_wq =
			alloc_ordered_workqueue("free_qp_wq", WQ_MEM_RECLAIM);
		if (!rf->free_qp_wq) {
			status = IRDMA_ERR_NO_MEMORY;
			break;
		}

		rf->free_cqbuf_wq =
			alloc_ordered_workqueue("free_cqbuf_wq", WQ_MEM_RECLAIM);
		if (!rf->free_cqbuf_wq) {
			status = IRDMA_ERR_NO_MEMORY;
			break;
		}
		dev->ccq_ops->ccq_arm(dev->ccq);
		dev_info(to_device(dev), "IRDMA hardware initialization successful\n");
		return 0;
	} while (0);

	pr_err("IRDMA hardware initialization FAILED init_state=%d status=%d\n",
	       rf->init_state, status);
	irdma_deinit_ctrl_hw(rf);
	return status;
}

/**
 * irdma_initialize_hw_resources - initialize hw resource during open
 * @rf: RDMA PCI function
 */
u32 irdma_initialize_hw_rsrc(struct irdma_pci_f *rf)
{
	unsigned long num_pds;
	u32 rsrc_size;
	u32 max_mr;
	u32 max_qp;
	u32 max_cq;
	u32 arp_table_size;
	u32 mrdrvbits;
	void *rsrc_ptr;
	u32 num_ahs;
	u32 num_mcg;

	if (rf->rdma_ver != IRDMA_GEN_1) {
		rf->allocated_ws_nodes =
			kcalloc(BITS_TO_LONGS(IRDMA_MAX_WS_NODES),
				sizeof(unsigned long), GFP_KERNEL);
		if (!rf->allocated_ws_nodes)
			return -ENOMEM;

		set_bit(0, rf->allocated_ws_nodes);
		rf->max_ws_node_id = IRDMA_MAX_WS_NODES;
	}
	max_qp = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_QP].cnt;
	max_cq = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt;
	max_mr = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_MR].cnt;
	arp_table_size = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_ARP].cnt;
	rf->max_cqe = rf->sc_dev.hw_attrs.uk_attrs.max_hw_cq_size;
	num_pds = rf->sc_dev.hw_attrs.max_hw_pds;
	rsrc_size = sizeof(struct irdma_arp_entry) * arp_table_size;
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(max_qp);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(max_mr);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(max_cq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(num_pds);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(arp_table_size);
	num_ahs = max_qp * 4;
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(num_ahs);
	num_mcg = max_qp;
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(num_mcg);
	rsrc_size += sizeof(struct irdma_qp **) * max_qp;

	rf->mem_rsrc = kzalloc(rsrc_size, GFP_KERNEL);
	if (!rf->mem_rsrc) {
		kfree(rf->allocated_ws_nodes);
		rf->allocated_ws_nodes = NULL;
		return -ENOMEM;
	}

	rf->max_qp = max_qp;
	rf->max_mr = max_mr;
	rf->max_cq = max_cq;
	rf->max_pd = num_pds;
	rf->arp_table_size = arp_table_size;
	rf->arp_table = (struct irdma_arp_entry *)rf->mem_rsrc;
	rsrc_ptr = rf->mem_rsrc +
		   (sizeof(struct irdma_arp_entry) * arp_table_size);

	rf->max_ah = num_ahs;
	rf->max_mcg = num_mcg;
	rf->allocated_qps = rsrc_ptr;
	rf->allocated_cqs = &rf->allocated_qps[BITS_TO_LONGS(max_qp)];
	rf->allocated_mrs = &rf->allocated_cqs[BITS_TO_LONGS(max_cq)];
	rf->allocated_pds = &rf->allocated_mrs[BITS_TO_LONGS(max_mr)];
	rf->allocated_ahs = &rf->allocated_pds[BITS_TO_LONGS(num_pds)];
	rf->allocated_mcgs = &rf->allocated_ahs[BITS_TO_LONGS(num_ahs)];
	rf->allocated_arps = &rf->allocated_mcgs[BITS_TO_LONGS(num_mcg)];
	rf->qp_table = (struct irdma_qp **)
		       (&rf->allocated_arps[BITS_TO_LONGS(arp_table_size)]);

	set_bit(0, rf->allocated_mrs);
	set_bit(0, rf->allocated_qps);
	set_bit(0, rf->allocated_cqs);
	set_bit(0, rf->allocated_pds);
	set_bit(0, rf->allocated_arps);
	set_bit(0, rf->allocated_ahs);
	set_bit(0, rf->allocated_mcgs);
	set_bit(2, rf->allocated_qps); /* qp 2 IEQ */
	set_bit(1, rf->allocated_qps); /* qp 1 ILQ */
	set_bit(1, rf->allocated_cqs);
	set_bit(1, rf->allocated_pds);
	set_bit(2, rf->allocated_cqs);
	set_bit(2, rf->allocated_pds);

	spin_lock_init(&rf->rsrc_lock);
	spin_lock_init(&rf->arp_lock);
	spin_lock_init(&rf->qptable_lock);
	spin_lock_init(&rf->qh_list_lock);

	INIT_LIST_HEAD(&rf->mc_qht_list.list);
	/* stag index mask has a minimum of 14 bits */
	mrdrvbits = 24 - max(get_count_order(rf->max_mr), 14);
	rf->mr_stagmask = ~(((1 << mrdrvbits) - 1) << (32 - mrdrvbits));

	return 0;
}

/**
 * irdma_cqp_ce_handler - handle cqp completions
 * @rf: RDMA PCI function
 * @cq: cq for cqp completions
 */
void irdma_cqp_ce_handler(struct irdma_pci_f *rf, struct irdma_sc_cq *cq)
{
	struct irdma_cqp_request *cqp_request;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	u32 cqe_count = 0;
	struct irdma_ccq_cqe_info info;
	unsigned long flags;
	int ret;

	do {
		memset(&info, 0, sizeof(info));
		spin_lock_irqsave(&rf->cqp.compl_lock, flags);
		ret = dev->ccq_ops->ccq_get_cqe_info(cq, &info);
		spin_unlock_irqrestore(&rf->cqp.compl_lock, flags);
		if (ret)
			break;

		cqp_request = (struct irdma_cqp_request *)
			      (unsigned long)info.scratch;
		if (info.error)
			irdma_debug(dev, IRDMA_DEBUG_ERR,
				    "opcode = 0x%x maj_err_code = 0x%x min_err_code = 0x%x\n",
				    info.op_code, info.maj_err_code,
				    info.min_err_code);
		if (cqp_request) {
			cqp_request->compl_info.maj_err_code = info.maj_err_code;
			cqp_request->compl_info.min_err_code = info.min_err_code;
			cqp_request->compl_info.op_ret_val = info.op_ret_val;
			cqp_request->compl_info.error = info.error;

			if (cqp_request->waiting) {
				cqp_request->request_done = true;
				wake_up(&cqp_request->waitq);
				irdma_put_cqp_request(&rf->cqp, cqp_request);
			} else {
				if (cqp_request->callback_fcn)
					cqp_request->callback_fcn(cqp_request,
								  1);
				irdma_put_cqp_request(&rf->cqp, cqp_request);
			}
		}

		cqe_count++;
	} while (1);

	if (cqe_count) {
		irdma_process_bh(dev);
		dev->ccq_ops->ccq_arm(cq);
	}
}

/**
 * irdma_iwarp_ce_handler - handle iwarp completions
 * @iwcq: iwarp cq receiving event
 */
static void irdma_iwarp_ce_handler(struct irdma_sc_cq *iwcq)
{
	struct irdma_cq *cq = iwcq->back_cq;

	if (cq->ibcq.comp_handler)
		cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
}

/**
 * irdma_puda_ce_handler - handle puda completion events
 * @rf: RDMA PCI function
 * @cq: puda completion q for event
 */
static void irdma_puda_ce_handler(struct irdma_pci_f *rf,
				  struct irdma_sc_cq *cq)
{
	struct irdma_sc_dev *dev = (struct irdma_sc_dev *)&rf->sc_dev;
	enum irdma_status_code status;
	u32 compl_error;

	do {
		status = irdma_puda_poll_cmpl(dev, cq, &compl_error);
		if (status == IRDMA_ERR_Q_EMPTY)
			break;
		if (status) {
			irdma_debug(dev, IRDMA_DEBUG_ERR, "puda status = %d\n",
				    status);
			break;
		}
		if (compl_error) {
			irdma_debug(dev, IRDMA_DEBUG_ERR,
				    "puda compl_err  =0x%x\n", compl_error);
			break;
		}
	} while (1);

	dev->ccq_ops->ccq_arm(cq);
}

/**
 * cqp_thread - Handle cqp completions
 * @context: Pointer to RDMA PCI Function
 */
int cqp_compl_thread(void *context)
{
	struct irdma_pci_f *rf = context;
	struct irdma_sc_cq *cq = &rf->ccq.sc_cq;

	do {
		if (down_interruptible(&rf->cqp.cqp_compl_sem))
			return 0;
		if (rf->stop_cqp_thread)
			return 0;
		irdma_cqp_ce_handler(rf, cq);
	} while (!kthread_should_stop());

	return 0;
}

/**
 * irdma_process_ceq - handle ceq for completions
 * @rf: RDMA PCI function
 * @ceq: ceq having cq for completion
 */
void irdma_process_ceq(struct irdma_pci_f *rf, struct irdma_ceq *ceq)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_sc_ceq *sc_ceq;
	struct irdma_sc_cq *cq;

	sc_ceq = &ceq->sc_ceq;
	do {
		cq = dev->ceq_ops->process_ceq(dev, sc_ceq);
		if (!cq)
			break;

		if (cq->cq_type == IRDMA_CQ_TYPE_CQP)
			up(&rf->cqp.cqp_compl_sem);
		else if (cq->cq_type == IRDMA_CQ_TYPE_IWARP)
			irdma_iwarp_ce_handler(cq);
		else if ((cq->cq_type == IRDMA_CQ_TYPE_ILQ) ||
			 (cq->cq_type == IRDMA_CQ_TYPE_IEQ))
			irdma_puda_ce_handler(rf, cq);
	} while (1);
}

/**
 * irdma_next_iw_state - modify qp state
 * @iwqp: iwarp qp to modify
 * @state: next state for qp
 * @del_hash: del hash
 * @term: term message
 * @termlen: length of term message
 */
void irdma_next_iw_state(struct irdma_qp *iwqp, u8 state, u8 del_hash, u8 term,
			 u8 termlen)
{
	struct irdma_modify_qp_info info = {};

	info.next_iwarp_state = state;
	info.remove_hash_idx = del_hash;
	info.cq_num_valid = true;
	info.arp_cache_idx_valid = true;
	info.dont_send_term = true;
	info.dont_send_fin = true;
	info.termlen = termlen;

	if (term & IRDMAQP_TERM_SEND_TERM_ONLY)
		info.dont_send_term = false;
	if (term & IRDMAQP_TERM_SEND_FIN_ONLY)
		info.dont_send_fin = false;
	if (iwqp->sc_qp.term_flags && state == IRDMA_QP_STATE_ERROR)
		info.reset_tcp_conn = true;
	iwqp->hw_iwarp_state = state;
	irdma_hw_modify_qp(iwqp->iwdev, iwqp, &info, 0);
}

/**
 * irdma_process_aeq - handle aeq events
 * @rf: RDMA PCI function
 */
void irdma_process_aeq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_aeq *aeq = &rf->aeq;
	struct irdma_sc_aeq *sc_aeq = &aeq->sc_aeq;
	struct irdma_aeqe_info aeinfo;
	struct irdma_aeqe_info *info = &aeinfo;
	int ret;
	struct irdma_qp *iwqp = NULL;
	struct irdma_sc_cq *cq = NULL;
	struct irdma_cq *iwcq = NULL;
	struct irdma_sc_qp *qp = NULL;
	struct irdma_qp_host_ctx_info *ctx_info = NULL;
	unsigned long flags;

	u32 aeqcnt = 0;
	bool roce_mode = false;

	if (!sc_aeq->size)
		return;

	do {
		memset(info, 0, sizeof(*info));
		ret = dev->aeq_ops->get_next_aeqe(sc_aeq, info);
		if (ret)
			break;

		aeqcnt++;
		irdma_debug(dev, IRDMA_DEBUG_AEQ,
			    "ae_id = 0x%x bool qp=%d qp_id = %d\n", info->ae_id,
			    info->qp, info->qp_cq_id);
		if (info->qp) {
			spin_lock_irqsave(&rf->qptable_lock, flags);
			iwqp = rf->qp_table[info->qp_cq_id];
			if (!iwqp) {
				spin_unlock_irqrestore(&rf->qptable_lock,
						       flags);
				irdma_debug(dev, IRDMA_DEBUG_AEQ,
					    "qp_id %d is already freed\n",
					    info->qp_cq_id);
				continue;
			}
			irdma_add_ref(&iwqp->ibqp);
			spin_unlock_irqrestore(&rf->qptable_lock, flags);
			qp = &iwqp->sc_qp;
			spin_lock_irqsave(&iwqp->lock, flags);
			iwqp->hw_tcp_state = info->tcp_state;
			iwqp->hw_iwarp_state = info->iwarp_state;
			iwqp->last_aeq = info->ae_id;
			spin_unlock_irqrestore(&iwqp->lock, flags);
			ctx_info = &iwqp->ctx_info;
			if (rdma_protocol_roce(&iwqp->iwdev->iwibdev->ibdev, 1))
				roce_mode = true;
			if (roce_mode)
				ctx_info->roce_info->err_rq_idx_valid = true;
			else
				ctx_info->iwarp_info->err_rq_idx_valid = true;
		} else {
			if (info->ae_id != IRDMA_AE_CQ_OPERATION_ERROR)
				continue;
		}

		switch (info->ae_id) {
			struct irdma_cm_node *cm_node;
		case IRDMA_AE_LLP_CONNECTION_ESTABLISHED:
			cm_node = iwqp->cm_node;
			if (cm_node->accept_pend) {
				atomic_dec(&cm_node->listener->pend_accepts_cnt);
				cm_node->accept_pend = 0;
			}
			iwqp->rts_ae_rcvd = 1;
			wake_up_interruptible(&iwqp->waitq);
			break;
		case IRDMA_AE_LLP_FIN_RECEIVED:
		case IRDMA_AE_RDMAP_ROE_BAD_LLP_CLOSE:
			if (qp->term_flags)
				break;
			if (atomic_inc_return(&iwqp->close_timer_started) == 1) {
				iwqp->hw_tcp_state = IRDMA_TCP_STATE_CLOSE_WAIT;
				if (iwqp->hw_tcp_state == IRDMA_TCP_STATE_CLOSE_WAIT &&
				    iwqp->ibqp_state == IB_QPS_RTS) {
					irdma_next_iw_state(iwqp,
							    IRDMA_QP_STATE_CLOSING,
							    0, 0, 0);
					irdma_cm_disconn(iwqp);
				}
				iwqp->cm_id->add_ref(iwqp->cm_id);
				irdma_schedule_cm_timer(iwqp->cm_node,
							(struct irdma_puda_buf *)iwqp,
							IRDMA_TIMER_TYPE_CLOSE,
							1, 0);
			}
			break;
		case IRDMA_AE_LLP_CLOSE_COMPLETE:
			if (qp->term_flags)
				irdma_terminate_done(qp, 0);
			else
				irdma_cm_disconn(iwqp);
			break;
		case IRDMA_AE_BAD_CLOSE:
			/* fall through */
		case IRDMA_AE_RESET_SENT:
			irdma_next_iw_state(iwqp, IRDMA_QP_STATE_ERROR, 1, 0,
					    0);
			irdma_cm_disconn(iwqp);
			break;
		case IRDMA_AE_LLP_CONNECTION_RESET:
			if (atomic_read(&iwqp->close_timer_started))
				break;
			irdma_cm_disconn(iwqp);
			break;
		case IRDMA_AE_QP_SUSPEND_COMPLETE:
			atomic_dec(&iwqp->sc_qp.vsi->qp_suspend_reqs);
			wake_up(&iwqp->iwdev->suspend_wq);
			break;
		case IRDMA_AE_TERMINATE_SENT:
			irdma_terminate_send_fin(qp);
			break;
		case IRDMA_AE_LLP_TERMINATE_RECEIVED:
			irdma_terminate_received(qp, info);
			break;
		case IRDMA_AE_CQ_OPERATION_ERROR:
			irdma_debug(dev, IRDMA_DEBUG_ERR,
				    "Processing an iWARP related AE for CQ misc = 0x%04X\n",
				    info->ae_id);
			cq = (struct irdma_sc_cq *)(unsigned long)
			     info->compl_ctx;

			iwcq = (struct irdma_cq *)cq->back_cq;

			if (iwcq->ibcq.event_handler) {
				struct ib_event ibevent;

				ibevent.device = iwcq->ibcq.device;
				ibevent.event = IB_EVENT_CQ_ERR;
				ibevent.element.cq = &iwcq->ibcq;
				iwcq->ibcq.event_handler(&ibevent,
							 iwcq->ibcq.cq_context);
			}
			break;
		case IRDMA_AE_LLP_DOUBT_REACHABILITY:
			break;
		case IRDMA_AE_PRIV_OPERATION_DENIED:
		case IRDMA_AE_STAG_ZERO_INVALID:
		case IRDMA_AE_IB_RREQ_AND_Q1_FULL:
		case IRDMA_AE_DDP_UBE_INVALID_DDP_VERSION:
		case IRDMA_AE_DDP_UBE_INVALID_MO:
		case IRDMA_AE_DDP_UBE_INVALID_QN:
		case IRDMA_AE_DDP_NO_L_BIT:
		case IRDMA_AE_RDMAP_ROE_INVALID_RDMAP_VERSION:
		case IRDMA_AE_RDMAP_ROE_UNEXPECTED_OPCODE:
		case IRDMA_AE_ROE_INVALID_RDMA_READ_REQUEST:
		case IRDMA_AE_ROE_INVALID_RDMA_WRITE_OR_READ_RESP:
		case IRDMA_AE_INVALID_ARP_ENTRY:
		case IRDMA_AE_INVALID_TCP_OPTION_RCVD:
		case IRDMA_AE_STALE_ARP_ENTRY:
		case IRDMA_AE_LLP_RECEIVED_MPA_CRC_ERROR:
		case IRDMA_AE_LLP_SEGMENT_TOO_SMALL:
		case IRDMA_AE_LLP_SYN_RECEIVED:
		case IRDMA_AE_LLP_TOO_MANY_RETRIES:
		case IRDMA_AE_LCE_QP_CATASTROPHIC:
		case IRDMA_AE_LCE_FUNCTION_CATASTROPHIC:
		case IRDMA_AE_LCE_CQ_CATASTROPHIC:
		case IRDMA_AE_UDA_XMIT_DGRAM_TOO_LONG:
			if (roce_mode)
				ctx_info->roce_info->err_rq_idx_valid = false;
			else
				ctx_info->iwarp_info->err_rq_idx_valid = false;
			/* fall through */
		default:
			if (roce_mode) {
				if (!info->sq && ctx_info->roce_info->err_rq_idx_valid) {
					ctx_info->roce_info->err_rq_idx = info->wqe_idx;
					ret = dev->iw_priv_qp_ops->qp_setctx_roce(&iwqp->sc_qp,
										  iwqp->host_ctx.va,
										  ctx_info);
				}
				irdma_cm_disconn(iwqp);
				break;
			}
			if (!info->sq && ctx_info->iwarp_info->err_rq_idx_valid) {
				ctx_info->iwarp_info->err_rq_idx = info->wqe_idx;
				ctx_info->tcp_info_valid = false;
				ctx_info->iwarp_info_valid = false;
				ret = dev->iw_priv_qp_ops->qp_setctx(&iwqp->sc_qp,
								     iwqp->host_ctx.va,
								     ctx_info);
			}
			irdma_terminate_connection(qp, info);
			break;
		}
		if (info->qp)
			irdma_rem_ref(&iwqp->ibqp);
	} while (1);

	if (aeqcnt)
		dev->aeq_ops->repost_aeq_entries(dev, aeqcnt);
}

/**
 * irdma_del_mac_entry - remove a mac entry from the hw table
 * @rf: RDMA PCI function
 * @idx: the index of the mac ip address to delete
 */
void irdma_del_local_mac_entry(struct irdma_pci_f *rf, u16 idx)
{
	struct irdma_cqp *iwcqp = &rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	enum irdma_status_code status = 0;

	cqp_request = irdma_get_cqp_request(iwcqp, true);
	if (!cqp_request) {
		pr_err("cqp_request memory failed\n");
		return;
	}

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = IRDMA_OP_DELETE_LOCAL_MAC_ENTRY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.del_local_mac_entry.cqp = &iwcqp->sc_cqp;
	cqp_info->in.u.del_local_mac_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->in.u.del_local_mac_entry.entry_idx = idx;
	cqp_info->in.u.del_local_mac_entry.ignore_ref_count = 0;
	status = irdma_handle_cqp_op(rf, cqp_request);
	if (status)
		pr_err("CQP-OP Del MAC entry fail");
}

/**
 * irdma_add_mac_entry - add a mac ip address entry to the hw table
 * @rf: RDMA PCI function
 * @mac_addr: pointer to mac address
 * @idx: the index of the mac ip address to add
 */
int irdma_add_local_mac_entry(struct irdma_pci_f *rf, u8 *mac_addr, u16 idx)
{
	struct irdma_local_mac_entry_info *info;
	struct irdma_cqp *iwcqp = &rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	enum irdma_status_code status = 0;

	cqp_request = irdma_get_cqp_request(iwcqp, true);
	if (!cqp_request) {
		pr_err("cqp_request memory failed\n");
		return IRDMA_ERR_NO_MEMORY;
	}

	cqp_info = &cqp_request->info;
	cqp_info->post_sq = 1;
	info = &cqp_info->in.u.add_local_mac_entry.info;
	ether_addr_copy(info->mac_addr, mac_addr);
	info->entry_idx = idx;
	cqp_info->in.u.add_local_mac_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->cqp_cmd = IRDMA_OP_ADD_LOCAL_MAC_ENTRY;
	cqp_info->in.u.add_local_mac_entry.cqp = &iwcqp->sc_cqp;
	cqp_info->in.u.add_local_mac_entry.scratch = (uintptr_t)cqp_request;
	status = irdma_handle_cqp_op(rf, cqp_request);
	if (status)
		pr_err("CQP-OP Add MAC entry fail");

	return status;
}

/**
 * irdma_alloc_local_mac_entry - allocate a mac entry
 * @rf: RDMA PCI function
 * @mac_tbl_idx: the index of the new mac address
 *
 * Allocate a mac address entry and update the mac_tbl_idx
 * to hold the index of the newly created mac address
 * Return 0 if successful, otherwise return error
 */
int irdma_alloc_local_mac_entry(struct irdma_pci_f *rf, u16 *mac_tbl_idx)
{
	struct irdma_cqp *iwcqp = &rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	enum irdma_status_code status = 0;

	cqp_request = irdma_get_cqp_request(iwcqp, true);
	if (!cqp_request) {
		pr_err("cqp_request memory failed\n");
		return IRDMA_ERR_NO_MEMORY;
	}

	/* increment refcount, because we need the cqp request ret value */
	atomic_inc(&cqp_request->refcount);
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = IRDMA_OP_ALLOC_LOCAL_MAC_ENTRY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.alloc_local_mac_entry.cqp = &iwcqp->sc_cqp;
	cqp_info->in.u.alloc_local_mac_entry.scratch = (uintptr_t)cqp_request;
	status = irdma_handle_cqp_op(rf, cqp_request);
	if (!status)
		*mac_tbl_idx = (u16)cqp_request->compl_info.op_ret_val;
	else
		pr_err("CQP-OP Alloc MAC entry fail");
	/* decrement refcount and free the cqp request, if no longer used */
	irdma_put_cqp_request(iwcqp, cqp_request);

	return status;
}

/**
 * irdma_cqp_manage_apbvt_cmd - send cqp command manage apbvt
 * @iwdev: iwarp device
 * @accel_local_port: port for apbvt
 * @add_port: add ordelete port
 */
static enum irdma_status_code
irdma_cqp_manage_apbvt_cmd(struct irdma_device *iwdev, u16 accel_local_port,
			   bool add_port)
{
	struct irdma_apbvt_info *info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	enum irdma_status_code status;

	cqp_request = irdma_get_cqp_request(&iwdev->rf->cqp, add_port);
	if (!cqp_request)
		return IRDMA_ERR_NO_MEMORY;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.manage_apbvt_entry.info;
	memset(info, 0, sizeof(*info));
	info->add = add_port;
	info->port = accel_local_port;
	cqp_info->cqp_cmd = IRDMA_OP_MANAGE_APBVT_ENTRY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.manage_apbvt_entry.cqp = &iwdev->rf->cqp.sc_cqp;
	cqp_info->in.u.manage_apbvt_entry.scratch = (uintptr_t)cqp_request;
	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	if (status)
		irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_ERR,
			    "CQP-OP Manage APBVT entry fail");

	return status;
}

/**
 * irdma_manage_apbvt - add or delete tcp port
 * @iwdev: iwarp device
 * @accel_local_port: port for apbvt
 * @add_port: add or delete port
 */
enum irdma_status_code irdma_manage_apbvt(struct irdma_device *iwdev,
					  u16 accel_local_port, bool add_port)
{
	struct irdma_cm_core *cm_core = &iwdev->cm_core;
	enum irdma_status_code status = 0;
	unsigned long flags;
	bool in_use;

	/* apbvt_lock is held across CQP delete APBVT OP (non-waiting) to
	 * protect against race where add APBVT CQP can race ahead of the delete
	 * APBVT for same port.
	 */
	if (add_port) {
		spin_lock_irqsave(&cm_core->apbvt_lock, flags);
		in_use = __test_and_set_bit(accel_local_port,
					    cm_core->ports_in_use);
		spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);
		if (in_use)
			return 0;
		return irdma_cqp_manage_apbvt_cmd(iwdev, accel_local_port,
						  true);
	} else {
		spin_lock_irqsave(&cm_core->apbvt_lock, flags);
		in_use = irdma_port_in_use(cm_core, accel_local_port);
		if (in_use) {
			spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);
			return 0;
		}
		__clear_bit(accel_local_port, cm_core->ports_in_use);
		status = irdma_cqp_manage_apbvt_cmd(iwdev, accel_local_port,
						    false);
		spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);
		return status;
	}
}

/**
 * irdma_manage_arp_cache - manage hw arp cache
 * @rf: RDMA PCI function
 * @mac_addr: mac address ptr
 * @ip_addr: ip addr for arp cache
 * @ipv4: flag inicating IPv4
 * @action: add, delete or modify
 */
void irdma_manage_arp_cache(struct irdma_pci_f *rf, unsigned char *mac_addr,
			    u32 *ip_addr, bool ipv4, u32 action)
{
	struct irdma_add_arp_cache_entry_info *info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int arp_index;

	arp_index = irdma_arp_table(rf, ip_addr, ipv4, mac_addr, action);
	if (arp_index == -1)
		return;

	cqp_request = irdma_get_cqp_request(&rf->cqp, false);
	if (!cqp_request)
		return;

	cqp_info = &cqp_request->info;
	if (action == IRDMA_ARP_ADD) {
		cqp_info->cqp_cmd = IRDMA_OP_ADD_ARP_CACHE_ENTRY;
		info = &cqp_info->in.u.add_arp_cache_entry.info;
		memset(info, 0, sizeof(*info));
		info->arp_index = (u16)arp_index;
		info->permanent = true;
		ether_addr_copy(info->mac_addr, mac_addr);
		cqp_info->in.u.add_arp_cache_entry.scratch =
			(uintptr_t)cqp_request;
		cqp_info->in.u.add_arp_cache_entry.cqp = &rf->cqp.sc_cqp;
	} else {
		cqp_info->cqp_cmd = IRDMA_OP_DELETE_ARP_CACHE_ENTRY;
		cqp_info->in.u.del_arp_cache_entry.scratch =
			(uintptr_t)cqp_request;
		cqp_info->in.u.del_arp_cache_entry.cqp = &rf->cqp.sc_cqp;
		cqp_info->in.u.del_arp_cache_entry.arp_index = arp_index;
	}

	cqp_info->in.u.add_arp_cache_entry.cqp = &rf->cqp.sc_cqp;
	cqp_info->in.u.add_arp_cache_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->post_sq = 1;
	if (irdma_handle_cqp_op(rf, cqp_request))
		irdma_debug(&rf->sc_dev, IRDMA_DEBUG_ERR,
			    "CQP-OP Add/Del Arp Cache entry fail");
}

/**
 * irdma_send_syn_cqp_callback - do syn/ack after qhash
 * @cqp_request: qhash cqp completion
 * @send_ack: flag send ack
 */
static void irdma_send_syn_cqp_callback(struct irdma_cqp_request *cqp_request,
					u32 send_ack)
{
	irdma_send_syn(cqp_request->param, send_ack);
}

/**
 * irdma_manage_qhash - add or modify qhash
 * @iwdev: iwarp device
 * @cminfo: cm info for qhash
 * @etype: type (syn or quad)
 * @mtype: type of qhash
 * @cmnode: cmnode associated with connection
 * @wait: wait for completion
 */
enum irdma_status_code
irdma_manage_qhash(struct irdma_device *iwdev, struct irdma_cm_info *cminfo,
		   enum irdma_quad_entry_type etype,
		   enum irdma_quad_hash_manage_type mtype, void *cmnode,
		   bool wait)
{
	struct irdma_qhash_table_info *info;
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	enum irdma_status_code status;
	struct irdma_cqp *iwcqp = &iwdev->rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;

	cqp_request = irdma_get_cqp_request(iwcqp, wait);
	if (!cqp_request)
		return IRDMA_ERR_NO_MEMORY;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.manage_qhash_table_entry.info;
	memset(info, 0, sizeof(*info));
	info->vsi = &iwdev->vsi;
	info->manage = mtype;
	info->entry_type = etype;
	if (cminfo->vlan_id != 0xFFFF) {
		info->vlan_valid = true;
		info->vlan_id = cminfo->vlan_id;
	} else {
		info->vlan_valid = false;
	}
	info->ipv4_valid = cminfo->ipv4;
	info->user_pri = cminfo->user_pri;
	ether_addr_copy(info->mac_addr, iwdev->netdev->dev_addr);
	info->qp_num = cminfo->qh_qpid;
	info->dest_port = cminfo->loc_port;
	info->dest_ip[0] = cminfo->loc_addr[0];
	info->dest_ip[1] = cminfo->loc_addr[1];
	info->dest_ip[2] = cminfo->loc_addr[2];
	info->dest_ip[3] = cminfo->loc_addr[3];
	if (etype == IRDMA_QHASH_TYPE_TCP_ESTABLISHED ||
	    etype == IRDMA_QHASH_TYPE_UDP_UNICAST ||
	    etype == IRDMA_QHASH_TYPE_UDP_MCAST ||
	    etype == IRDMA_QHASH_TYPE_ROCE_MCAST ||
	    etype == IRDMA_QHASH_TYPE_ROCEV2_HW) {
		info->src_port = cminfo->rem_port;
		info->src_ip[0] = cminfo->rem_addr[0];
		info->src_ip[1] = cminfo->rem_addr[1];
		info->src_ip[2] = cminfo->rem_addr[2];
		info->src_ip[3] = cminfo->rem_addr[3];
	}
	if (cmnode) {
		cqp_request->callback_fcn = irdma_send_syn_cqp_callback;
		cqp_request->param = cmnode;
	}
	if (info->ipv4_valid)
		irdma_debug(dev, IRDMA_DEBUG_CM,
			    "%s IP=%pI4, port=%d, mac=%pM, vlan_id=%d\n",
			    !mtype ? "DELETE" : "ADD", info->dest_ip,
			    info->dest_port, info->mac_addr, cminfo->vlan_id);
	else
		irdma_debug(dev, IRDMA_DEBUG_CM,
			    "%s IP=%pI6, port=%d, mac=%pM, vlan_id=%d\n",
			    !mtype ? "DELETE" : "ADD",
			    info->dest_ip,
			    info->dest_port, info->mac_addr, cminfo->vlan_id);
	cqp_info->in.u.manage_qhash_table_entry.cqp = &iwdev->rf->cqp.sc_cqp;
	cqp_info->in.u.manage_qhash_table_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->cqp_cmd = IRDMA_OP_MANAGE_QHASH_TABLE_ENTRY;
	cqp_info->post_sq = 1;
	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	if (status)
		irdma_debug(dev, IRDMA_DEBUG_ERR,
			    "CQP-OP Manage Qhash Entry fail");

	return status;
}

/**
 * irdma_hw_flush_wqes - flush qp's wqe
 * @rf: RDMA PCI function
 * @qp: hardware control qp
 * @info: info for flush
 * @wait: flag wait for completion
 */
enum irdma_status_code irdma_hw_flush_wqes(struct irdma_pci_f *rf,
					   struct irdma_sc_qp *qp,
					   struct irdma_qp_flush_info *info,
					   bool wait)
{
	enum irdma_status_code status;
	struct irdma_qp_flush_info *hw_info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct irdma_qp *iwqp = qp->qp_uk.back_qp;
	unsigned long flags = 0;

	cqp_request = irdma_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return IRDMA_ERR_NO_MEMORY;

	cqp_info = &cqp_request->info;
	hw_info = &cqp_request->info.in.u.qp_flush_wqes.info;
	memcpy(hw_info, info, sizeof(*hw_info));
	cqp_info->cqp_cmd = IRDMA_OP_QP_FLUSH_WQES;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_flush_wqes.qp = qp;
	cqp_info->in.u.qp_flush_wqes.scratch = (uintptr_t)cqp_request;
	status = irdma_handle_cqp_op(rf, cqp_request);
	if (status) {
		irdma_debug(&rf->sc_dev, IRDMA_DEBUG_ERR,
			    "CQP-OP Flush WQE's fail");
		complete(&iwqp->sq_drained);
		complete(&iwqp->rq_drained);
		qp->qp_uk.sq_flush_complete = true;
		qp->qp_uk.rq_flush_complete = true;
		return status;
	}

	if (!cqp_request->compl_info.maj_err_code) {
		if (info->rq) {
			if (cqp_request->compl_info.min_err_code == IRDMA_CQP_COMPL_SQ_WQE_FLUSHED ||
			    cqp_request->compl_info.min_err_code == 0) {
				/* RQ WQE flush was requested but did not happen */
				qp->qp_uk.rq_flush_complete = true;
				complete(&iwqp->rq_drained);
			}
		}
		if (info->sq) {
			if (cqp_request->compl_info.min_err_code == IRDMA_CQP_COMPL_RQ_WQE_FLUSHED ||
			    cqp_request->compl_info.min_err_code == 0) {
				spin_lock_irqsave(&iwqp->lock, flags);
				/* Handling case where WQE is posted to empty SQ when
				 * flush has not completed
				 */
				if (IRDMA_RING_MORE_WORK(qp->qp_uk.sq_ring)) {
					spin_unlock_irqrestore(&iwqp->lock, flags);
					cqp_request->waiting = false;
					info->rq = false;
					qp->flush_sq = false;
					irdma_handle_cqp_op(rf, cqp_request);
				} else {
					/* SQ WQE flush was requested but did not happen */
					spin_unlock_irqrestore(&iwqp->lock, flags);
					qp->qp_uk.sq_flush_complete = true;
					complete(&iwqp->sq_drained);
				}
			} else {
				spin_lock_irqsave(&iwqp->lock, flags);
				if (!IRDMA_RING_MORE_WORK(qp->qp_uk.sq_ring)) {
					spin_unlock_irqrestore(&iwqp->lock, flags);
					qp->qp_uk.sq_flush_complete = true;
					complete(&iwqp->sq_drained);
				} else {
					spin_unlock_irqrestore(&iwqp->lock, flags);
				}
			}
		}
	}

	return 0;
}

/**
 * irdma_gen_ae - generate AE
 * @rf: RDMA PCI function
 * @qp: qp associated with AE
 * @info: info for ae
 * @wait: wait for completion
 */
void irdma_gen_ae(struct irdma_pci_f *rf, struct irdma_sc_qp *qp,
		  struct irdma_gen_ae_info *info, bool wait)
{
	struct irdma_gen_ae_info *ae_info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;

	cqp_request = irdma_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return;

	cqp_info = &cqp_request->info;
	ae_info = &cqp_request->info.in.u.gen_ae.info;
	memcpy(ae_info, info, sizeof(*ae_info));
	cqp_info->cqp_cmd = IRDMA_OP_GEN_AE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.gen_ae.qp = qp;
	cqp_info->in.u.gen_ae.scratch = (uintptr_t)cqp_request;
	if (irdma_handle_cqp_op(rf, cqp_request))
		irdma_debug(&rf->sc_dev, IRDMA_DEBUG_ERR,
			    "CQP OP failed attempting to generate ae_code=0x%x\n",
			    info->ae_code);
}

/**
 * irdma_get_ib_wc - return change flush code to IB's
 * @opcode: iwarp flush code
 */
static enum ib_wc_status irdma_get_ib_wc(enum irdma_flush_opcode opcode)
{
	switch (opcode) {
	case FLUSH_PROT_ERR:
		return IB_WC_LOC_PROT_ERR;
	case FLUSH_REM_ACCESS_ERR:
		return IB_WC_REM_ACCESS_ERR;
	case FLUSH_LOC_QP_OP_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case FLUSH_REM_OP_ERR:
		return IB_WC_REM_OP_ERR;
	case FLUSH_LOC_LEN_ERR:
		return IB_WC_LOC_LEN_ERR;
	case FLUSH_GENERAL_ERR:
		return IB_WC_GENERAL_ERR;
	case FLUSH_FATAL_ERR:
	default:
		return IB_WC_FATAL_ERR;
	}
}

/**
 * irdma_set_flush_info - set flush info
 * @pinfo: set flush info
 * @min: minor err
 * @maj: major err
 * @opcode: flush error code
 */
static void irdma_set_flush_info(struct irdma_qp_flush_info *pinfo, u16 *min,
				 u16 *maj, enum irdma_flush_opcode opcode)
{
	*min = (u16)irdma_get_ib_wc(opcode);
	*maj = CQE_MAJOR_DRV;
	pinfo->userflushcode = true;
}

/**
 * irdma_flush_wqes - flush wqe for qp
 * @rf: RDMA PCI function
 * @iwqp: qp to flush wqes
 */
void irdma_flush_wqes(struct irdma_pci_f *rf, struct irdma_qp *iwqp)
{
	struct irdma_qp_flush_info info = {};
	struct irdma_sc_qp *qp = &iwqp->sc_qp;

	info.sq = true;
	info.rq = true;
	if (qp->term_flags) {
		irdma_set_flush_info(&info, &info.sq_minor_code,
				     &info.sq_major_code, qp->flush_code);
		irdma_set_flush_info(&info, &info.rq_minor_code,
				     &info.rq_major_code, qp->flush_code);
	}
	(void)irdma_hw_flush_wqes(rf, &iwqp->sc_qp, &info, true);
}
