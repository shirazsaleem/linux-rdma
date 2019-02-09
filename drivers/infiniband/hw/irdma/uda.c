// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2019, Intel Corporation. */

#include "osdep.h"
#include "status.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "protos.h"
#include "uda.h"
#include "uda_d.h"

/**
 * irdma_sc_ah_init - initialize sc ah struct
 * @dev: sc device struct
 * @ah: sc ah ptr
 */
static void irdma_sc_init_ah(struct irdma_sc_dev *dev, struct irdma_sc_ah *ah)
{
	ah->dev = dev;
}

/**
 * irdma_sc_access_ah() - Create, modify or delete AH
 * @cqp: struct for cqp hw
 * @info: ah information
 * @op: Operation
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code irdma_sc_access_ah(struct irdma_sc_cqp *cqp,
						 struct irdma_ah_info *info,
						 u32 op, u64 scratch)
{
	__le64 *wqe;
	u64 qw1, qw2;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return IRDMA_ERR_RING_FULL;

	set_64bit_val(wqe, 0, LS_64_1(info->mac_addr[5], 16) |
					 LS_64_1(info->mac_addr[4], 24) |
					 LS_64_1(info->mac_addr[3], 32) |
					 LS_64_1(info->mac_addr[2], 40) |
					 LS_64_1(info->mac_addr[1], 48) |
					 LS_64_1(info->mac_addr[0], 56));

	qw1 = LS_64(info->pd_idx, IRDMA_UDA_CQPSQ_MAV_PDINDEXLO) |
	      LS_64(info->tc_tos, IRDMA_UDA_CQPSQ_MAV_TC) |
	      LS_64(info->vlan_tag, IRDMA_UDAQPC_VLANTAG);

	qw2 = LS_64(info->dst_arpindex, IRDMA_UDA_CQPSQ_MAV_ARPINDEX) |
	      LS_64(info->flow_label, IRDMA_UDA_CQPSQ_MAV_FLOWLABEL) |
	      LS_64(info->hop_ttl, IRDMA_UDA_CQPSQ_MAV_HOPLIMIT) |
	      LS_64(info->pd_idx >> 16, IRDMA_UDA_CQPSQ_MAV_PDINDEXHI);

	if (!info->ipv4_valid) {
		set_64bit_val(wqe, 40,
			      LS_64(info->dest_ip_addr[0], IRDMA_UDA_CQPSQ_MAV_ADDR0) |
			      LS_64(info->dest_ip_addr[1], IRDMA_UDA_CQPSQ_MAV_ADDR1));
		set_64bit_val(wqe, 32,
			      LS_64(info->dest_ip_addr[2], IRDMA_UDA_CQPSQ_MAV_ADDR2) |
			      LS_64(info->dest_ip_addr[3], IRDMA_UDA_CQPSQ_MAV_ADDR3));

		set_64bit_val(wqe, 56,
			      LS_64(info->src_ip_addr[0], IRDMA_UDA_CQPSQ_MAV_ADDR0) |
			      LS_64(info->src_ip_addr[1], IRDMA_UDA_CQPSQ_MAV_ADDR1));
		set_64bit_val(wqe, 48,
			      LS_64(info->src_ip_addr[2], IRDMA_UDA_CQPSQ_MAV_ADDR2) |
			      LS_64(info->src_ip_addr[3], IRDMA_UDA_CQPSQ_MAV_ADDR3));
	} else {
		set_64bit_val(wqe, 32,
			      LS_64(info->dest_ip_addr[0], IRDMA_UDA_CQPSQ_MAV_ADDR3));

		set_64bit_val(wqe, 48,
			      LS_64(info->src_ip_addr[0], IRDMA_UDA_CQPSQ_MAV_ADDR3));
	}

	set_64bit_val(wqe, 8, qw1);
	set_64bit_val(wqe, 16, qw2);

	dma_wmb(); /* need write block before writing WQE header */

	set_64bit_val(
		wqe, 24,
		LS_64(cqp->polarity, IRDMA_UDA_CQPSQ_MAV_WQEVALID) |
		LS_64(op, IRDMA_UDA_CQPSQ_MAV_OPCODE) |
		LS_64(info->do_lpbk, IRDMA_UDA_CQPSQ_MAV_DOLOOPBACKK) |
		LS_64(info->ipv4_valid, IRDMA_UDA_CQPSQ_MAV_IPV4VALID) |
		LS_64(info->ah_idx, IRDMA_UDA_CQPSQ_MAV_AVIDX) |
		LS_64(info->insert_vlan_tag,
		      IRDMA_UDA_CQPSQ_MAV_INSERTVLANTAG));

	irdma_debug_buf(cqp->dev, IRDMA_DEBUG_WQE, "MANAGE_AH WQE", wqe,
			IRDMA_CQP_WQE_SIZE * 8);
	irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_create_ah() - Create AH
 * @cqp: struct for cqp hw
 * @info: ah information
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code irdma_sc_create_ah(struct irdma_sc_cqp *cqp,
						 struct irdma_ah_info *info,
						 u64 scratch)
{
	return irdma_sc_access_ah(cqp, info, IRDMA_CQP_OP_CREATE_ADDR_HANDLE,
				  scratch);
}

/**
 * irdma_sc_modify_ah() - Modify AH
 * @cqp: struct for cqp hw
 * @info: ah information
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code irdma_sc_modify_ah(struct irdma_sc_cqp *cqp,
						 struct irdma_ah_info *info,
						 u64 scratch)
{
	return irdma_sc_access_ah(cqp, info, IRDMA_CQP_OP_MODIFY_ADDR_HANDLE,
				  scratch);
}

/**
 * irdma_sc_destroy_ah() - Delete AH
 * @cqp: struct for cqp hw
 * @info: ah information
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code irdma_sc_destroy_ah(struct irdma_sc_cqp *cqp,
						  struct irdma_ah_info *info,
						  u64 scratch)
{
	return irdma_sc_access_ah(cqp, info, IRDMA_CQP_OP_DESTROY_ADDR_HANDLE,
				  scratch);
}

/**
 * create_mg_ctx() - create a mcg context
 * @info: multicast group context info
 */
static enum irdma_status_code
irdma_create_mg_ctx(struct irdma_mcast_grp_info *info)
{
	struct irdma_mcast_grp_ctx_entry_info *entry_info = NULL;
	u8 idx = 0; /* index in the array */
	u8 ctx_idx = 0; /* index in the MG context */

	memset(info->dma_mem_mc.va, 0, IRDMA_MAX_MGS_PER_CTX * sizeof(u64));

	for (idx = 0; idx < IRDMA_MAX_MGS_PER_CTX; idx++) {
		entry_info = &info->mg_ctx_info[idx];
		if (entry_info->valid_entry) {
			set_64bit_val((__le64 *)info->dma_mem_mc.va,
				      ctx_idx * sizeof(u64),
				      LS_64(entry_info->dest_port, IRDMA_UDA_MGCTX_DESTPORT) |
				      LS_64(entry_info->valid_entry, IRDMA_UDA_MGCTX_VALIDENT) |
				      LS_64(entry_info->qp_id, IRDMA_UDA_MGCTX_QPID));
			ctx_idx++;
		}
	}

	return 0;
}

/**
 * irdma_access_mcast_grp() - Access mcast group based on op
 * @cqp: Control QP
 * @info: multicast group context info
 * @op: operation to perform
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code
irdma_access_mcast_grp(struct irdma_sc_cqp *cqp,
		       struct irdma_mcast_grp_info *info, u32 op, u64 scratch)
{
	__le64 *wqe;
	enum irdma_status_code ret_code = 0;

	if (info->mg_id >= IRDMA_UDA_MAX_FSI_MGS) {
		irdma_debug(cqp->dev, IRDMA_DEBUG_WQE, "mg_id out of range\n");
		return IRDMA_ERR_PARAM;
	}

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe) {
		irdma_debug(cqp->dev, IRDMA_DEBUG_WQE, "ring full\n");
		return IRDMA_ERR_RING_FULL;
	}

	ret_code = irdma_create_mg_ctx(info);
	if (ret_code)
		return ret_code;

	set_64bit_val(wqe, 32, info->dma_mem_mc.pa);
	set_64bit_val(wqe, 16,
		      LS_64(info->vlan_id, IRDMA_UDA_CQPSQ_MG_VLANID) |
		      LS_64(info->qs_handle, IRDMA_UDA_CQPSQ_QS_HANDLE));
	set_64bit_val(wqe, 0, LS_64_1(info->dest_mac_addr[5], 0) |
					 LS_64_1(info->dest_mac_addr[4], 8) |
					 LS_64_1(info->dest_mac_addr[3], 16) |
					 LS_64_1(info->dest_mac_addr[2], 24) |
					 LS_64_1(info->dest_mac_addr[1], 32) |
					 LS_64_1(info->dest_mac_addr[0], 40));
	set_64bit_val(wqe, 8,
		      LS_64(info->hmc_fcn_id, IRDMA_UDA_CQPSQ_MG_HMC_FCN_ID));

	if (!info->ipv4_valid) {
		set_64bit_val(wqe, 56,
			      LS_64(info->dest_ip_addr[0], IRDMA_UDA_CQPSQ_MAV_ADDR0) |
			      LS_64(info->dest_ip_addr[1], IRDMA_UDA_CQPSQ_MAV_ADDR1));
		set_64bit_val(wqe, 48,
			      LS_64(info->dest_ip_addr[2], IRDMA_UDA_CQPSQ_MAV_ADDR2) |
			      LS_64(info->dest_ip_addr[3], IRDMA_UDA_CQPSQ_MAV_ADDR3));
	} else {
		set_64bit_val(wqe, 48,
			      LS_64(info->dest_ip_addr[0], IRDMA_UDA_CQPSQ_MAV_ADDR3));
	}

	dma_wmb(); /* need write memory block before writing the WQE header. */

	set_64bit_val(wqe, 24,
		      LS_64(cqp->polarity, IRDMA_UDA_CQPSQ_MG_WQEVALID) |
		      LS_64(op, IRDMA_UDA_CQPSQ_MG_OPCODE) |
		      LS_64(info->mg_id, IRDMA_UDA_CQPSQ_MG_MGIDX) |
		      LS_64(info->vlan_valid, IRDMA_UDA_CQPSQ_MG_VLANVALID) |
		      LS_64(info->ipv4_valid, IRDMA_UDA_CQPSQ_MG_IPV4VALID));

	irdma_debug_buf(cqp->dev, IRDMA_DEBUG_WQE, "MANAGE_MCG WQE", wqe,
			IRDMA_CQP_WQE_SIZE * 8);
	irdma_debug_buf(cqp->dev, IRDMA_DEBUG_WQE, "MCG_HOST CTX WQE",
			info->dma_mem_mc.va, IRDMA_MAX_MGS_PER_CTX * 8);
	irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_create_mcast_grp() - Create mcast group.
 * @cqp: Control QP
 * @info: multicast group context info
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code
irdma_sc_create_mcast_grp(struct irdma_sc_cqp *cqp,
			  struct irdma_mcast_grp_info *info, u64 scratch)
{
	return irdma_access_mcast_grp(cqp, info, IRDMA_CQP_OP_CREATE_MCAST_GRP,
				      scratch);
}

/**
 * irdma_sc_modify_mcast_grp() - Modify mcast group
 * @cqp: Control QP
 * @info: multicast group context info
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code
irdma_sc_modify_mcast_grp(struct irdma_sc_cqp *cqp,
			  struct irdma_mcast_grp_info *info, u64 scratch)
{
	return irdma_access_mcast_grp(cqp, info, IRDMA_CQP_OP_MODIFY_MCAST_GRP,
				      scratch);
}

/**
 * irdma_sc_destroy_mcast_grp() - Destroys mcast group
 * @cqp: Control QP
 * @info: multicast group context info
 * @scratch: u64 saved to be used during cqp completion
 */
static enum irdma_status_code
irdma_sc_destroy_mcast_grp(struct irdma_sc_cqp *cqp,
			   struct irdma_mcast_grp_info *info, u64 scratch)
{
	return irdma_access_mcast_grp(cqp, info, IRDMA_CQP_OP_DESTROY_MCAST_GRP,
				      scratch);
}

/**
 * irdma_compare_mgs - Compares two multicast group structures
 * @entry1: Multcast group info
 * @entry2: Multcast group info in context
 */
static bool irdma_compare_mgs(struct irdma_mcast_grp_ctx_entry_info *entry1,
			      struct irdma_mcast_grp_ctx_entry_info *entry2)
{
	if (entry1->dest_port == entry2->dest_port &&
	    entry1->qp_id == entry2->qp_id)
		return true;
	else
		return false;
}

/**
 * irdma_sc_add_mcast_grp - Allocates mcast group entry in ctx
 * @ctx: Multcast group context
 * @mg: Multcast group info
 */
static enum irdma_status_code
irdma_sc_add_mcast_grp(struct irdma_mcast_grp_info *ctx,
		       struct irdma_mcast_grp_ctx_entry_info *mg)
{
	u32 idx;
	enum irdma_status_code ret_code = IRDMA_ERR_NO_MEMORY;
	bool free_entry_found = false;
	u32 free_entry_idx = 0;

	/* find either an identical or a free entry for a multicast group */
	for (idx = 0; idx < IRDMA_MAX_MGS_PER_CTX; idx++) {
		if (ctx->mg_ctx_info[idx].valid_entry) {
			if (irdma_compare_mgs(&ctx->mg_ctx_info[idx], mg)) {
				ctx->mg_ctx_info[idx].use_cnt++;
				return 0;
			}
			continue;
		}
		if (!free_entry_found) {
			free_entry_found = true;
			free_entry_idx = idx;
		}
	}

	if (free_entry_found) {
		ctx->mg_ctx_info[free_entry_idx] = *mg;
		ctx->mg_ctx_info[free_entry_idx].valid_entry = true;
		ctx->mg_ctx_info[free_entry_idx].use_cnt = 1;
		ctx->no_of_mgs++;
		ret_code = 0;
	}

	return ret_code;
}

/**
 * irdma_sc_del_mcast_grp - Delete mcast group
 * @ctx: Multcast group context
 * @mg: Multcast group info
 *
 * Finds and removes a specific mulicast group from context, all
 * parameters must match to remove a multicast group.
 */
static enum irdma_status_code
irdma_sc_del_mcast_grp(struct irdma_mcast_grp_info *ctx,
		       struct irdma_mcast_grp_ctx_entry_info *mg)
{
	u32 idx;
	enum irdma_status_code ret_code = IRDMA_ERR_PARAM;

	/* find an entry in multicast group context */
	for (idx = 0; idx < IRDMA_MAX_MGS_PER_CTX; idx++) {
		if (!ctx->mg_ctx_info[idx].valid_entry)
			continue;

		if (irdma_compare_mgs(mg, &ctx->mg_ctx_info[idx])) {
			ctx->mg_ctx_info[idx].use_cnt--;

			if (ctx->mg_ctx_info[idx].use_cnt == 0) {
				ctx->mg_ctx_info[idx].valid_entry = false;
				ctx->no_of_mgs--;
				/* Remove gap if element was not the last */
				if (idx != ctx->no_of_mgs &&
				    ctx->no_of_mgs > 0) {
					memcpy(&ctx->mg_ctx_info[idx],
					       &ctx->mg_ctx_info[ctx->no_of_mgs - 1],
					       sizeof(ctx->mg_ctx_info[idx]));
					ctx->mg_ctx_info[ctx->no_of_mgs - 1].valid_entry = false;
				}
			}

			ret_code = 0;
			goto exit;
		}
	}
exit:
	return ret_code;
}

struct irdma_uda_ops irdma_uda_ops = {
	.init_ah = irdma_sc_init_ah,
	.create_ah = irdma_sc_create_ah,
	.modify_ah = irdma_sc_modify_ah,
	.destroy_ah = irdma_sc_destroy_ah,
	.mcast_grp_create = irdma_sc_create_mcast_grp,
	.mcast_grp_modify = irdma_sc_modify_mcast_grp,
	.mcast_grp_destroy = irdma_sc_destroy_mcast_grp,
	.mcast_grp_add = irdma_sc_add_mcast_grp,
	.mcast_grp_del = irdma_sc_del_mcast_grp,
};
