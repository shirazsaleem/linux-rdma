// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018, Mellanox Technologies inc.  All rights reserved.
 */

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <rdma/uverbs_types.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/mlx5_user_ioctl_cmds.h>
#include <rdma/mlx5_user_ioctl_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/uverbs_std_types.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/fs.h>
#include "mlx5_ib.h"

#define UVERBS_MODULE_NAME mlx5_ib
#include <rdma/uverbs_named_ioctl.h>

enum devx_obj_flags {
	DEVX_OBJ_FLAGS_INDIRECT_MKEY = 1 << 0,
	DEVX_OBJ_FLAGS_DCT = 1 << 1,
};

struct devx_async_data {
	struct mlx5_ib_dev *mdev;
	struct list_head list;
	struct ib_uobject *fd_uobj;
	struct mlx5_async_work cb_work;
	u16 cmd_out_len;
	/* must be last field in this structure */
	struct mlx5_ib_uapi_devx_async_cmd_hdr hdr;
};

#define MLX5_MAX_DESTROY_INBOX_SIZE_DW MLX5_ST_SZ_DW(delete_fte_in)
struct devx_obj {
	struct mlx5_core_dev	*mdev;
	u64			obj_id;
	u32			dinlen; /* destroy inbox length */
	u32			dinbox[MLX5_MAX_DESTROY_INBOX_SIZE_DW];
	u32			flags;
	union {
		struct mlx5_ib_devx_mr	devx_mr;
		struct mlx5_core_dct	core_dct;
	};
};

struct devx_umem {
	struct mlx5_core_dev		*mdev;
	struct ib_umem			*umem;
	u32				page_offset;
	int				page_shift;
	int				ncont;
	u32				dinlen;
	u32				dinbox[MLX5_ST_SZ_DW(general_obj_in_cmd_hdr)];
};

struct devx_umem_reg_cmd {
	void				*in;
	u32				inlen;
	u32				out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];
};

static struct mlx5_ib_ucontext *
devx_ufile2uctx(const struct uverbs_attr_bundle *attrs)
{
	return to_mucontext(ib_uverbs_get_ucontext(attrs));
}

int mlx5_ib_devx_create(struct mlx5_ib_dev *dev, bool is_user)
{
	u32 in[MLX5_ST_SZ_DW(create_uctx_in)] = {0};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	void *uctx;
	int err;
	u16 uid;
	u32 cap = 0;

	/* 0 means not supported */
	if (!MLX5_CAP_GEN(dev->mdev, log_max_uctx))
		return -EINVAL;

	uctx = MLX5_ADDR_OF(create_uctx_in, in, uctx);
	if (is_user && capable(CAP_NET_RAW) &&
	    (MLX5_CAP_GEN(dev->mdev, uctx_cap) & MLX5_UCTX_CAP_RAW_TX))
		cap |= MLX5_UCTX_CAP_RAW_TX;

	MLX5_SET(create_uctx_in, in, opcode, MLX5_CMD_OP_CREATE_UCTX);
	MLX5_SET(uctx, uctx, cap, cap);

	err = mlx5_cmd_exec(dev->mdev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	uid = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);
	return uid;
}

void mlx5_ib_devx_destroy(struct mlx5_ib_dev *dev, u16 uid)
{
	u32 in[MLX5_ST_SZ_DW(destroy_uctx_in)] = {0};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};

	MLX5_SET(destroy_uctx_in, in, opcode, MLX5_CMD_OP_DESTROY_UCTX);
	MLX5_SET(destroy_uctx_in, in, uid, uid);

	mlx5_cmd_exec(dev->mdev, in, sizeof(in), out, sizeof(out));
}

bool mlx5_ib_devx_is_flow_dest(void *obj, int *dest_id, int *dest_type)
{
	struct devx_obj *devx_obj = obj;
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, devx_obj->dinbox, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_DESTROY_TIR:
		*dest_type = MLX5_FLOW_DESTINATION_TYPE_TIR;
		*dest_id = MLX5_GET(general_obj_in_cmd_hdr, devx_obj->dinbox,
				    obj_id);
		return true;

	case MLX5_CMD_OP_DESTROY_FLOW_TABLE:
		*dest_type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		*dest_id = MLX5_GET(destroy_flow_table_in, devx_obj->dinbox,
				    table_id);
		return true;
	default:
		return false;
	}
}

bool mlx5_ib_devx_is_flow_counter(void *obj, u32 *counter_id)
{
	struct devx_obj *devx_obj = obj;
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, devx_obj->dinbox, opcode);

	if (opcode == MLX5_CMD_OP_DEALLOC_FLOW_COUNTER) {
		*counter_id = MLX5_GET(dealloc_flow_counter_in,
				       devx_obj->dinbox,
				       flow_counter_id);
		return true;
	}

	return false;
}

/*
 * As the obj_id in the firmware is not globally unique the object type
 * must be considered upon checking for a valid object id.
 * For that the opcode of the creator command is encoded as part of the obj_id.
 */
static u64 get_enc_obj_id(u16 opcode, u32 obj_id)
{
	return ((u64)opcode << 32) | obj_id;
}

static u64 devx_get_obj_id(const void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);
	u64 obj_id;

	switch (opcode) {
	case MLX5_CMD_OP_MODIFY_GENERAL_OBJECT:
	case MLX5_CMD_OP_QUERY_GENERAL_OBJECT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_GENERAL_OBJECT,
					MLX5_GET(general_obj_in_cmd_hdr, in,
						 obj_id));
		break;
	case MLX5_CMD_OP_QUERY_MKEY:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_MKEY,
					MLX5_GET(query_mkey_in, in,
						 mkey_index));
		break;
	case MLX5_CMD_OP_QUERY_CQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_CQ,
					MLX5_GET(query_cq_in, in, cqn));
		break;
	case MLX5_CMD_OP_MODIFY_CQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_CQ,
					MLX5_GET(modify_cq_in, in, cqn));
		break;
	case MLX5_CMD_OP_QUERY_SQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_SQ,
					MLX5_GET(query_sq_in, in, sqn));
		break;
	case MLX5_CMD_OP_MODIFY_SQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_SQ,
					MLX5_GET(modify_sq_in, in, sqn));
		break;
	case MLX5_CMD_OP_QUERY_RQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_RQ,
					MLX5_GET(query_rq_in, in, rqn));
		break;
	case MLX5_CMD_OP_MODIFY_RQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_RQ,
					MLX5_GET(modify_rq_in, in, rqn));
		break;
	case MLX5_CMD_OP_QUERY_RMP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_RMP,
					MLX5_GET(query_rmp_in, in, rmpn));
		break;
	case MLX5_CMD_OP_MODIFY_RMP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_RMP,
					MLX5_GET(modify_rmp_in, in, rmpn));
		break;
	case MLX5_CMD_OP_QUERY_RQT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_RQT,
					MLX5_GET(query_rqt_in, in, rqtn));
		break;
	case MLX5_CMD_OP_MODIFY_RQT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_RQT,
					MLX5_GET(modify_rqt_in, in, rqtn));
		break;
	case MLX5_CMD_OP_QUERY_TIR:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_TIR,
					MLX5_GET(query_tir_in, in, tirn));
		break;
	case MLX5_CMD_OP_MODIFY_TIR:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_TIR,
					MLX5_GET(modify_tir_in, in, tirn));
		break;
	case MLX5_CMD_OP_QUERY_TIS:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_TIS,
					MLX5_GET(query_tis_in, in, tisn));
		break;
	case MLX5_CMD_OP_MODIFY_TIS:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_TIS,
					MLX5_GET(modify_tis_in, in, tisn));
		break;
	case MLX5_CMD_OP_QUERY_FLOW_TABLE:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_FLOW_TABLE,
					MLX5_GET(query_flow_table_in, in,
						 table_id));
		break;
	case MLX5_CMD_OP_MODIFY_FLOW_TABLE:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_FLOW_TABLE,
					MLX5_GET(modify_flow_table_in, in,
						 table_id));
		break;
	case MLX5_CMD_OP_QUERY_FLOW_GROUP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_FLOW_GROUP,
					MLX5_GET(query_flow_group_in, in,
						 group_id));
		break;
	case MLX5_CMD_OP_QUERY_FLOW_TABLE_ENTRY:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY,
					MLX5_GET(query_fte_in, in,
						 flow_index));
		break;
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY,
					MLX5_GET(set_fte_in, in, flow_index));
		break;
	case MLX5_CMD_OP_QUERY_Q_COUNTER:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_ALLOC_Q_COUNTER,
					MLX5_GET(query_q_counter_in, in,
						 counter_set_id));
		break;
	case MLX5_CMD_OP_QUERY_FLOW_COUNTER:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_ALLOC_FLOW_COUNTER,
					MLX5_GET(query_flow_counter_in, in,
						 flow_counter_id));
		break;
	case MLX5_CMD_OP_QUERY_MODIFY_HEADER_CONTEXT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT,
					MLX5_GET(general_obj_in_cmd_hdr, in,
						 obj_id));
		break;
	case MLX5_CMD_OP_QUERY_SCHEDULING_ELEMENT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT,
					MLX5_GET(query_scheduling_element_in,
						 in, scheduling_element_id));
		break;
	case MLX5_CMD_OP_MODIFY_SCHEDULING_ELEMENT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT,
					MLX5_GET(modify_scheduling_element_in,
						 in, scheduling_element_id));
		break;
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT,
					MLX5_GET(add_vxlan_udp_dport_in, in,
						 vxlan_udp_port));
		break;
	case MLX5_CMD_OP_QUERY_L2_TABLE_ENTRY:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_SET_L2_TABLE_ENTRY,
					MLX5_GET(query_l2_table_entry_in, in,
						 table_index));
		break;
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_SET_L2_TABLE_ENTRY,
					MLX5_GET(set_l2_table_entry_in, in,
						 table_index));
		break;
	case MLX5_CMD_OP_QUERY_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(query_qp_in, in, qpn));
		break;
	case MLX5_CMD_OP_RST2INIT_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(rst2init_qp_in, in, qpn));
		break;
	case MLX5_CMD_OP_INIT2RTR_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(init2rtr_qp_in, in, qpn));
		break;
	case MLX5_CMD_OP_RTR2RTS_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(rtr2rts_qp_in, in, qpn));
		break;
	case MLX5_CMD_OP_RTS2RTS_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(rts2rts_qp_in, in, qpn));
		break;
	case MLX5_CMD_OP_SQERR2RTS_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(sqerr2rts_qp_in, in, qpn));
		break;
	case MLX5_CMD_OP_2ERR_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(qp_2err_in, in, qpn));
		break;
	case MLX5_CMD_OP_2RST_QP:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
					MLX5_GET(qp_2rst_in, in, qpn));
		break;
	case MLX5_CMD_OP_QUERY_DCT:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_DCT,
					MLX5_GET(query_dct_in, in, dctn));
		break;
	case MLX5_CMD_OP_QUERY_XRQ:
	case MLX5_CMD_OP_QUERY_XRQ_DC_PARAMS_ENTRY:
	case MLX5_CMD_OP_QUERY_XRQ_ERROR_PARAMS:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_XRQ,
					MLX5_GET(query_xrq_in, in, xrqn));
		break;
	case MLX5_CMD_OP_QUERY_XRC_SRQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_XRC_SRQ,
					MLX5_GET(query_xrc_srq_in, in,
						 xrc_srqn));
		break;
	case MLX5_CMD_OP_ARM_XRC_SRQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_XRC_SRQ,
					MLX5_GET(arm_xrc_srq_in, in, xrc_srqn));
		break;
	case MLX5_CMD_OP_QUERY_SRQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_SRQ,
					MLX5_GET(query_srq_in, in, srqn));
		break;
	case MLX5_CMD_OP_ARM_RQ:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_RQ,
					MLX5_GET(arm_rq_in, in, srq_number));
		break;
	case MLX5_CMD_OP_ARM_DCT_FOR_KEY_VIOLATION:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_DCT,
					MLX5_GET(drain_dct_in, in, dctn));
		break;
	case MLX5_CMD_OP_ARM_XRQ:
	case MLX5_CMD_OP_SET_XRQ_DC_PARAMS_ENTRY:
		obj_id = get_enc_obj_id(MLX5_CMD_OP_CREATE_XRQ,
					MLX5_GET(arm_xrq_in, in, xrqn));
		break;
	case MLX5_CMD_OP_QUERY_PACKET_REFORMAT_CONTEXT:
		obj_id = get_enc_obj_id
				(MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT,
				 MLX5_GET(query_packet_reformat_context_in,
					  in, packet_reformat_id));
		break;
	default:
		obj_id = 0;
	}

	return obj_id;
}

static bool devx_is_valid_obj_id(struct ib_uobject *uobj, const void *in)
{
	u64 obj_id = devx_get_obj_id(in);

	if (!obj_id)
		return false;

	switch (uobj_get_object_id(uobj)) {
	case UVERBS_OBJECT_CQ:
		return get_enc_obj_id(MLX5_CMD_OP_CREATE_CQ,
				      to_mcq(uobj->object)->mcq.cqn) ==
				      obj_id;

	case UVERBS_OBJECT_SRQ:
	{
		struct mlx5_core_srq *srq = &(to_msrq(uobj->object)->msrq);
		struct mlx5_ib_dev *dev = to_mdev(uobj->context->device);
		u16 opcode;

		switch (srq->common.res) {
		case MLX5_RES_XSRQ:
			opcode = MLX5_CMD_OP_CREATE_XRC_SRQ;
			break;
		case MLX5_RES_XRQ:
			opcode = MLX5_CMD_OP_CREATE_XRQ;
			break;
		default:
			if (!dev->mdev->issi)
				opcode = MLX5_CMD_OP_CREATE_SRQ;
			else
				opcode = MLX5_CMD_OP_CREATE_RMP;
		}

		return get_enc_obj_id(opcode,
				      to_msrq(uobj->object)->msrq.srqn) ==
				      obj_id;
	}

	case UVERBS_OBJECT_QP:
	{
		struct mlx5_ib_qp *qp = to_mqp(uobj->object);
		enum ib_qp_type	qp_type = qp->ibqp.qp_type;

		if (qp_type == IB_QPT_RAW_PACKET ||
		    (qp->flags & MLX5_IB_QP_UNDERLAY)) {
			struct mlx5_ib_raw_packet_qp *raw_packet_qp =
							 &qp->raw_packet_qp;
			struct mlx5_ib_rq *rq = &raw_packet_qp->rq;
			struct mlx5_ib_sq *sq = &raw_packet_qp->sq;

			return (get_enc_obj_id(MLX5_CMD_OP_CREATE_RQ,
					       rq->base.mqp.qpn) == obj_id ||
				get_enc_obj_id(MLX5_CMD_OP_CREATE_SQ,
					       sq->base.mqp.qpn) == obj_id ||
				get_enc_obj_id(MLX5_CMD_OP_CREATE_TIR,
					       rq->tirn) == obj_id ||
				get_enc_obj_id(MLX5_CMD_OP_CREATE_TIS,
					       sq->tisn) == obj_id);
		}

		if (qp_type == MLX5_IB_QPT_DCT)
			return get_enc_obj_id(MLX5_CMD_OP_CREATE_DCT,
					      qp->dct.mdct.mqp.qpn) == obj_id;

		return get_enc_obj_id(MLX5_CMD_OP_CREATE_QP,
				      qp->ibqp.qp_num) == obj_id;
	}

	case UVERBS_OBJECT_WQ:
		return get_enc_obj_id(MLX5_CMD_OP_CREATE_RQ,
				      to_mrwq(uobj->object)->core_qp.qpn) ==
				      obj_id;

	case UVERBS_OBJECT_RWQ_IND_TBL:
		return get_enc_obj_id(MLX5_CMD_OP_CREATE_RQT,
				      to_mrwq_ind_table(uobj->object)->rqtn) ==
				      obj_id;

	case MLX5_IB_OBJECT_DEVX_OBJ:
		return ((struct devx_obj *)uobj->object)->obj_id == obj_id;

	default:
		return false;
	}
}

static void devx_set_umem_valid(const void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_CREATE_MKEY:
		MLX5_SET(create_mkey_in, in, mkey_umem_valid, 1);
		break;
	case MLX5_CMD_OP_CREATE_CQ:
	{
		void *cqc;

		MLX5_SET(create_cq_in, in, cq_umem_valid, 1);
		cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);
		MLX5_SET(cqc, cqc, dbr_umem_valid, 1);
		break;
	}
	case MLX5_CMD_OP_CREATE_QP:
	{
		void *qpc;

		qpc = MLX5_ADDR_OF(create_qp_in, in, qpc);
		MLX5_SET(qpc, qpc, dbr_umem_valid, 1);
		MLX5_SET(create_qp_in, in, wq_umem_valid, 1);
		break;
	}

	case MLX5_CMD_OP_CREATE_RQ:
	{
		void *rqc, *wq;

		rqc = MLX5_ADDR_OF(create_rq_in, in, ctx);
		wq  = MLX5_ADDR_OF(rqc, rqc, wq);
		MLX5_SET(wq, wq, dbr_umem_valid, 1);
		MLX5_SET(wq, wq, wq_umem_valid, 1);
		break;
	}

	case MLX5_CMD_OP_CREATE_SQ:
	{
		void *sqc, *wq;

		sqc = MLX5_ADDR_OF(create_sq_in, in, ctx);
		wq = MLX5_ADDR_OF(sqc, sqc, wq);
		MLX5_SET(wq, wq, dbr_umem_valid, 1);
		MLX5_SET(wq, wq, wq_umem_valid, 1);
		break;
	}

	case MLX5_CMD_OP_MODIFY_CQ:
		MLX5_SET(modify_cq_in, in, cq_umem_valid, 1);
		break;

	case MLX5_CMD_OP_CREATE_RMP:
	{
		void *rmpc, *wq;

		rmpc = MLX5_ADDR_OF(create_rmp_in, in, ctx);
		wq = MLX5_ADDR_OF(rmpc, rmpc, wq);
		MLX5_SET(wq, wq, dbr_umem_valid, 1);
		MLX5_SET(wq, wq, wq_umem_valid, 1);
		break;
	}

	case MLX5_CMD_OP_CREATE_XRQ:
	{
		void *xrqc, *wq;

		xrqc = MLX5_ADDR_OF(create_xrq_in, in, xrq_context);
		wq = MLX5_ADDR_OF(xrqc, xrqc, wq);
		MLX5_SET(wq, wq, dbr_umem_valid, 1);
		MLX5_SET(wq, wq, wq_umem_valid, 1);
		break;
	}

	case MLX5_CMD_OP_CREATE_XRC_SRQ:
	{
		void *xrc_srqc;

		MLX5_SET(create_xrc_srq_in, in, xrc_srq_umem_valid, 1);
		xrc_srqc = MLX5_ADDR_OF(create_xrc_srq_in, in,
					xrc_srq_context_entry);
		MLX5_SET(xrc_srqc, xrc_srqc, dbr_umem_valid, 1);
		break;
	}

	default:
		return;
	}
}

static bool devx_is_obj_create_cmd(const void *in, u16 *opcode)
{
	*opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (*opcode) {
	case MLX5_CMD_OP_CREATE_GENERAL_OBJECT:
	case MLX5_CMD_OP_CREATE_MKEY:
	case MLX5_CMD_OP_CREATE_CQ:
	case MLX5_CMD_OP_ALLOC_PD:
	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
	case MLX5_CMD_OP_CREATE_RMP:
	case MLX5_CMD_OP_CREATE_SQ:
	case MLX5_CMD_OP_CREATE_RQ:
	case MLX5_CMD_OP_CREATE_RQT:
	case MLX5_CMD_OP_CREATE_TIR:
	case MLX5_CMD_OP_CREATE_TIS:
	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
	case MLX5_CMD_OP_ALLOC_FLOW_COUNTER:
	case MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT:
	case MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT:
	case MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_CREATE_QP:
	case MLX5_CMD_OP_CREATE_SRQ:
	case MLX5_CMD_OP_CREATE_XRC_SRQ:
	case MLX5_CMD_OP_CREATE_DCT:
	case MLX5_CMD_OP_CREATE_XRQ:
	case MLX5_CMD_OP_ATTACH_TO_MCG:
	case MLX5_CMD_OP_ALLOC_XRCD:
		return true;
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
	{
		u16 op_mod = MLX5_GET(set_fte_in, in, op_mod);
		if (op_mod == 0)
			return true;
		return false;
	}
	default:
		return false;
	}
}

static bool devx_is_obj_modify_cmd(const void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_MODIFY_GENERAL_OBJECT:
	case MLX5_CMD_OP_MODIFY_CQ:
	case MLX5_CMD_OP_MODIFY_RMP:
	case MLX5_CMD_OP_MODIFY_SQ:
	case MLX5_CMD_OP_MODIFY_RQ:
	case MLX5_CMD_OP_MODIFY_RQT:
	case MLX5_CMD_OP_MODIFY_TIR:
	case MLX5_CMD_OP_MODIFY_TIS:
	case MLX5_CMD_OP_MODIFY_FLOW_TABLE:
	case MLX5_CMD_OP_MODIFY_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_RST2INIT_QP:
	case MLX5_CMD_OP_INIT2RTR_QP:
	case MLX5_CMD_OP_RTR2RTS_QP:
	case MLX5_CMD_OP_RTS2RTS_QP:
	case MLX5_CMD_OP_SQERR2RTS_QP:
	case MLX5_CMD_OP_2ERR_QP:
	case MLX5_CMD_OP_2RST_QP:
	case MLX5_CMD_OP_ARM_XRC_SRQ:
	case MLX5_CMD_OP_ARM_RQ:
	case MLX5_CMD_OP_ARM_DCT_FOR_KEY_VIOLATION:
	case MLX5_CMD_OP_ARM_XRQ:
	case MLX5_CMD_OP_SET_XRQ_DC_PARAMS_ENTRY:
		return true;
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
	{
		u16 op_mod = MLX5_GET(set_fte_in, in, op_mod);

		if (op_mod == 1)
			return true;
		return false;
	}
	default:
		return false;
	}
}

static bool devx_is_obj_query_cmd(const void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_QUERY_GENERAL_OBJECT:
	case MLX5_CMD_OP_QUERY_MKEY:
	case MLX5_CMD_OP_QUERY_CQ:
	case MLX5_CMD_OP_QUERY_RMP:
	case MLX5_CMD_OP_QUERY_SQ:
	case MLX5_CMD_OP_QUERY_RQ:
	case MLX5_CMD_OP_QUERY_RQT:
	case MLX5_CMD_OP_QUERY_TIR:
	case MLX5_CMD_OP_QUERY_TIS:
	case MLX5_CMD_OP_QUERY_Q_COUNTER:
	case MLX5_CMD_OP_QUERY_FLOW_TABLE:
	case MLX5_CMD_OP_QUERY_FLOW_GROUP:
	case MLX5_CMD_OP_QUERY_FLOW_TABLE_ENTRY:
	case MLX5_CMD_OP_QUERY_FLOW_COUNTER:
	case MLX5_CMD_OP_QUERY_MODIFY_HEADER_CONTEXT:
	case MLX5_CMD_OP_QUERY_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_QUERY_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_QUERY_QP:
	case MLX5_CMD_OP_QUERY_SRQ:
	case MLX5_CMD_OP_QUERY_XRC_SRQ:
	case MLX5_CMD_OP_QUERY_DCT:
	case MLX5_CMD_OP_QUERY_XRQ:
	case MLX5_CMD_OP_QUERY_XRQ_DC_PARAMS_ENTRY:
	case MLX5_CMD_OP_QUERY_XRQ_ERROR_PARAMS:
	case MLX5_CMD_OP_QUERY_PACKET_REFORMAT_CONTEXT:
		return true;
	default:
		return false;
	}
}

static bool devx_is_whitelist_cmd(void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_QUERY_HCA_CAP:
	case MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT:
		return true;
	default:
		return false;
	}
}

static int devx_get_uid(struct mlx5_ib_ucontext *c, void *cmd_in)
{
	if (devx_is_whitelist_cmd(cmd_in)) {
		struct mlx5_ib_dev *dev;

		if (c->devx_uid)
			return c->devx_uid;

		dev = to_mdev(c->ibucontext.device);
		if (dev->devx_whitelist_uid)
			return dev->devx_whitelist_uid;

		return -EOPNOTSUPP;
	}

	if (!c->devx_uid)
		return -EINVAL;

	return c->devx_uid;
}
static bool devx_is_general_cmd(void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	if (opcode >= MLX5_CMD_OP_GENERAL_START &&
	    opcode < MLX5_CMD_OP_GENERAL_END)
		return true;

	switch (opcode) {
	case MLX5_CMD_OP_QUERY_HCA_CAP:
	case MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT:
	case MLX5_CMD_OP_QUERY_VPORT_STATE:
	case MLX5_CMD_OP_QUERY_ADAPTER:
	case MLX5_CMD_OP_QUERY_ISSI:
	case MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT:
	case MLX5_CMD_OP_QUERY_ROCE_ADDRESS:
	case MLX5_CMD_OP_QUERY_VNIC_ENV:
	case MLX5_CMD_OP_QUERY_VPORT_COUNTER:
	case MLX5_CMD_OP_GET_DROPPED_PACKET_LOG:
	case MLX5_CMD_OP_NOP:
	case MLX5_CMD_OP_QUERY_CONG_STATUS:
	case MLX5_CMD_OP_QUERY_CONG_PARAMS:
	case MLX5_CMD_OP_QUERY_CONG_STATISTICS:
		return true;
	default:
		return false;
	}
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_QUERY_EQN)(
	struct uverbs_attr_bundle *attrs)
{
	struct mlx5_ib_ucontext *c;
	struct mlx5_ib_dev *dev;
	int user_vector;
	int dev_eqn;
	unsigned int irqn;
	int err;

	if (uverbs_copy_from(&user_vector, attrs,
			     MLX5_IB_ATTR_DEVX_QUERY_EQN_USER_VEC))
		return -EFAULT;

	c = devx_ufile2uctx(attrs);
	if (IS_ERR(c))
		return PTR_ERR(c);
	dev = to_mdev(c->ibucontext.device);

	err = mlx5_vector2eqn(dev->mdev, user_vector, &dev_eqn, &irqn);
	if (err < 0)
		return err;

	if (uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_QUERY_EQN_DEV_EQN,
			   &dev_eqn, sizeof(dev_eqn)))
		return -EFAULT;

	return 0;
}

/*
 *Security note:
 * The hardware protection mechanism works like this: Each device object that
 * is subject to UAR doorbells (QP/SQ/CQ) gets a UAR ID (called uar_page in
 * the device specification manual) upon its creation. Then upon doorbell,
 * hardware fetches the object context for which the doorbell was rang, and
 * validates that the UAR through which the DB was rang matches the UAR ID
 * of the object.
 * If no match the doorbell is silently ignored by the hardware. Of course,
 * the user cannot ring a doorbell on a UAR that was not mapped to it.
 * Now in devx, as the devx kernel does not manipulate the QP/SQ/CQ command
 * mailboxes (except tagging them with UID), we expose to the user its UAR
 * ID, so it can embed it in these objects in the expected specification
 * format. So the only thing the user can do is hurt itself by creating a
 * QP/SQ/CQ with a UAR ID other than his, and then in this case other users
 * may ring a doorbell on its objects.
 * The consequence of that will be that another user can schedule a QP/SQ
 * of the buggy user for execution (just insert it to the hardware schedule
 * queue or arm its CQ for event generation), no further harm is expected.
 */
static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_QUERY_UAR)(
	struct uverbs_attr_bundle *attrs)
{
	struct mlx5_ib_ucontext *c;
	struct mlx5_ib_dev *dev;
	u32 user_idx;
	s32 dev_idx;

	c = devx_ufile2uctx(attrs);
	if (IS_ERR(c))
		return PTR_ERR(c);
	dev = to_mdev(c->ibucontext.device);

	if (uverbs_copy_from(&user_idx, attrs,
			     MLX5_IB_ATTR_DEVX_QUERY_UAR_USER_IDX))
		return -EFAULT;

	dev_idx = bfregn_to_uar_index(dev, &c->bfregi, user_idx, true);
	if (dev_idx < 0)
		return dev_idx;

	if (uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_QUERY_UAR_DEV_IDX,
			   &dev_idx, sizeof(dev_idx)))
		return -EFAULT;

	return 0;
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_OTHER)(
	struct uverbs_attr_bundle *attrs)
{
	struct mlx5_ib_ucontext *c;
	struct mlx5_ib_dev *dev;
	void *cmd_in = uverbs_attr_get_alloced_ptr(
		attrs, MLX5_IB_ATTR_DEVX_OTHER_CMD_IN);
	int cmd_out_len = uverbs_attr_get_len(attrs,
					MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT);
	void *cmd_out;
	int err;
	int uid;

	c = devx_ufile2uctx(attrs);
	if (IS_ERR(c))
		return PTR_ERR(c);
	dev = to_mdev(c->ibucontext.device);

	uid = devx_get_uid(c, cmd_in);
	if (uid < 0)
		return uid;

	/* Only white list of some general HCA commands are allowed for this method. */
	if (!devx_is_general_cmd(cmd_in))
		return -EINVAL;

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	MLX5_SET(general_obj_in_cmd_hdr, cmd_in, uid, uid);
	err = mlx5_cmd_exec(dev->mdev, cmd_in,
			    uverbs_attr_get_len(attrs, MLX5_IB_ATTR_DEVX_OTHER_CMD_IN),
			    cmd_out, cmd_out_len);
	if (err)
		return err;

	return uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT, cmd_out,
			      cmd_out_len);
}

static void devx_obj_build_destroy_cmd(void *in, void *out, void *din,
				       u32 *dinlen,
				       u32 *obj_id)
{
	u16 obj_type = MLX5_GET(general_obj_in_cmd_hdr, in, obj_type);
	u16 uid = MLX5_GET(general_obj_in_cmd_hdr, in, uid);

	*obj_id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);
	*dinlen = MLX5_ST_SZ_BYTES(general_obj_in_cmd_hdr);

	MLX5_SET(general_obj_in_cmd_hdr, din, obj_id, *obj_id);
	MLX5_SET(general_obj_in_cmd_hdr, din, uid, uid);

	switch (MLX5_GET(general_obj_in_cmd_hdr, in, opcode)) {
	case MLX5_CMD_OP_CREATE_GENERAL_OBJECT:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_GENERAL_OBJECT);
		MLX5_SET(general_obj_in_cmd_hdr, din, obj_type, obj_type);
		break;

	case MLX5_CMD_OP_CREATE_UMEM:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DESTROY_UMEM);
		break;
	case MLX5_CMD_OP_CREATE_MKEY:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_MKEY);
		break;
	case MLX5_CMD_OP_CREATE_CQ:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_CQ);
		break;
	case MLX5_CMD_OP_ALLOC_PD:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DEALLOC_PD);
		break;
	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DEALLOC_TRANSPORT_DOMAIN);
		break;
	case MLX5_CMD_OP_CREATE_RMP:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_RMP);
		break;
	case MLX5_CMD_OP_CREATE_SQ:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_SQ);
		break;
	case MLX5_CMD_OP_CREATE_RQ:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_RQ);
		break;
	case MLX5_CMD_OP_CREATE_RQT:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_RQT);
		break;
	case MLX5_CMD_OP_CREATE_TIR:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_TIR);
		break;
	case MLX5_CMD_OP_CREATE_TIS:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_TIS);
		break;
	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DEALLOC_Q_COUNTER);
		break;
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
		*dinlen = MLX5_ST_SZ_BYTES(destroy_flow_table_in);
		*obj_id = MLX5_GET(create_flow_table_out, out, table_id);
		MLX5_SET(destroy_flow_table_in, din, other_vport,
			 MLX5_GET(create_flow_table_in,  in, other_vport));
		MLX5_SET(destroy_flow_table_in, din, vport_number,
			 MLX5_GET(create_flow_table_in,  in, vport_number));
		MLX5_SET(destroy_flow_table_in, din, table_type,
			 MLX5_GET(create_flow_table_in,  in, table_type));
		MLX5_SET(destroy_flow_table_in, din, table_id, *obj_id);
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DESTROY_FLOW_TABLE);
		break;
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
		*dinlen = MLX5_ST_SZ_BYTES(destroy_flow_group_in);
		*obj_id = MLX5_GET(create_flow_group_out, out, group_id);
		MLX5_SET(destroy_flow_group_in, din, other_vport,
			 MLX5_GET(create_flow_group_in, in, other_vport));
		MLX5_SET(destroy_flow_group_in, din, vport_number,
			 MLX5_GET(create_flow_group_in, in, vport_number));
		MLX5_SET(destroy_flow_group_in, din, table_type,
			 MLX5_GET(create_flow_group_in, in, table_type));
		MLX5_SET(destroy_flow_group_in, din, table_id,
			 MLX5_GET(create_flow_group_in, in, table_id));
		MLX5_SET(destroy_flow_group_in, din, group_id, *obj_id);
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DESTROY_FLOW_GROUP);
		break;
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
		*dinlen = MLX5_ST_SZ_BYTES(delete_fte_in);
		*obj_id = MLX5_GET(set_fte_in, in, flow_index);
		MLX5_SET(delete_fte_in, din, other_vport,
			 MLX5_GET(set_fte_in,  in, other_vport));
		MLX5_SET(delete_fte_in, din, vport_number,
			 MLX5_GET(set_fte_in, in, vport_number));
		MLX5_SET(delete_fte_in, din, table_type,
			 MLX5_GET(set_fte_in, in, table_type));
		MLX5_SET(delete_fte_in, din, table_id,
			 MLX5_GET(set_fte_in, in, table_id));
		MLX5_SET(delete_fte_in, din, flow_index, *obj_id);
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY);
		break;
	case MLX5_CMD_OP_ALLOC_FLOW_COUNTER:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DEALLOC_FLOW_COUNTER);
		break;
	case MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DEALLOC_PACKET_REFORMAT_CONTEXT);
		break;
	case MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DEALLOC_MODIFY_HEADER_CONTEXT);
		break;
	case MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT:
		*dinlen = MLX5_ST_SZ_BYTES(destroy_scheduling_element_in);
		*obj_id = MLX5_GET(create_scheduling_element_out, out,
				   scheduling_element_id);
		MLX5_SET(destroy_scheduling_element_in, din,
			 scheduling_hierarchy,
			 MLX5_GET(create_scheduling_element_in, in,
				  scheduling_hierarchy));
		MLX5_SET(destroy_scheduling_element_in, din,
			 scheduling_element_id, *obj_id);
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DESTROY_SCHEDULING_ELEMENT);
		break;
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
		*dinlen = MLX5_ST_SZ_BYTES(delete_vxlan_udp_dport_in);
		*obj_id = MLX5_GET(add_vxlan_udp_dport_in, in, vxlan_udp_port);
		MLX5_SET(delete_vxlan_udp_dport_in, din, vxlan_udp_port, *obj_id);
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DELETE_VXLAN_UDP_DPORT);
		break;
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
		*dinlen = MLX5_ST_SZ_BYTES(delete_l2_table_entry_in);
		*obj_id = MLX5_GET(set_l2_table_entry_in, in, table_index);
		MLX5_SET(delete_l2_table_entry_in, din, table_index, *obj_id);
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DELETE_L2_TABLE_ENTRY);
		break;
	case MLX5_CMD_OP_CREATE_QP:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_QP);
		break;
	case MLX5_CMD_OP_CREATE_SRQ:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_SRQ);
		break;
	case MLX5_CMD_OP_CREATE_XRC_SRQ:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode,
			 MLX5_CMD_OP_DESTROY_XRC_SRQ);
		break;
	case MLX5_CMD_OP_CREATE_DCT:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_DCT);
		break;
	case MLX5_CMD_OP_CREATE_XRQ:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DESTROY_XRQ);
		break;
	case MLX5_CMD_OP_ATTACH_TO_MCG:
		*dinlen = MLX5_ST_SZ_BYTES(detach_from_mcg_in);
		MLX5_SET(detach_from_mcg_in, din, qpn,
			 MLX5_GET(attach_to_mcg_in, in, qpn));
		memcpy(MLX5_ADDR_OF(detach_from_mcg_in, din, multicast_gid),
		       MLX5_ADDR_OF(attach_to_mcg_in, in, multicast_gid),
		       MLX5_FLD_SZ_BYTES(attach_to_mcg_in, multicast_gid));
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DETACH_FROM_MCG);
		break;
	case MLX5_CMD_OP_ALLOC_XRCD:
		MLX5_SET(general_obj_in_cmd_hdr, din, opcode, MLX5_CMD_OP_DEALLOC_XRCD);
		break;
	default:
		/* The entry must match to one of the devx_is_obj_create_cmd */
		WARN_ON(true);
		break;
	}
}

static int devx_handle_mkey_indirect(struct devx_obj *obj,
				     struct mlx5_ib_dev *dev,
				     void *in, void *out)
{
	struct mlx5_mkey_table *table = &dev->mdev->priv.mkey_table;
	struct mlx5_ib_devx_mr *devx_mr = &obj->devx_mr;
	unsigned long flags;
	struct mlx5_core_mkey *mkey;
	void *mkc;
	u8 key;
	int err;

	mkey = &devx_mr->mmkey;
	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	key = MLX5_GET(mkc, mkc, mkey_7_0);
	mkey->key = mlx5_idx_to_mkey(
			MLX5_GET(create_mkey_out, out, mkey_index)) | key;
	mkey->type = MLX5_MKEY_INDIRECT_DEVX;
	mkey->iova = MLX5_GET64(mkc, mkc, start_addr);
	mkey->size = MLX5_GET64(mkc, mkc, len);
	mkey->pd = MLX5_GET(mkc, mkc, pd);
	devx_mr->ndescs = MLX5_GET(mkc, mkc, translations_octword_size);

	write_lock_irqsave(&table->lock, flags);
	err = radix_tree_insert(&table->tree, mlx5_base_mkey(mkey->key),
				mkey);
	write_unlock_irqrestore(&table->lock, flags);
	return err;
}

static int devx_handle_mkey_create(struct mlx5_ib_dev *dev,
				   struct devx_obj *obj,
				   void *in, int in_len)
{
	int min_len = MLX5_BYTE_OFF(create_mkey_in, memory_key_mkey_entry) +
			MLX5_FLD_SZ_BYTES(create_mkey_in,
			memory_key_mkey_entry);
	void *mkc;
	u8 access_mode;

	if (in_len < min_len)
		return -EINVAL;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	access_mode = MLX5_GET(mkc, mkc, access_mode_1_0);
	access_mode |= MLX5_GET(mkc, mkc, access_mode_4_2) << 2;

	if (access_mode == MLX5_MKC_ACCESS_MODE_KLMS ||
		access_mode == MLX5_MKC_ACCESS_MODE_KSM) {
		if (IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING))
			obj->flags |= DEVX_OBJ_FLAGS_INDIRECT_MKEY;
		return 0;
	}

	MLX5_SET(create_mkey_in, in, mkey_umem_valid, 1);
	return 0;
}

static void devx_free_indirect_mkey(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct devx_obj, devx_mr.rcu));
}

/* This function to delete from the radix tree needs to be called before
 * destroying the underlying mkey. Otherwise a race might occur in case that
 * other thread will get the same mkey before this one will be deleted,
 * in that case it will fail via inserting to the tree its own data.
 *
 * Note:
 * An error in the destroy is not expected unless there is some other indirect
 * mkey which points to this one. In a kernel cleanup flow it will be just
 * destroyed in the iterative destruction call. In a user flow, in case
 * the application didn't close in the expected order it's its own problem,
 * the mkey won't be part of the tree, in both cases the kernel is safe.
 */
static void devx_cleanup_mkey(struct devx_obj *obj)
{
	struct mlx5_mkey_table *table = &obj->mdev->priv.mkey_table;
	unsigned long flags;

	write_lock_irqsave(&table->lock, flags);
	radix_tree_delete(&table->tree, mlx5_base_mkey(obj->devx_mr.mmkey.key));
	write_unlock_irqrestore(&table->lock, flags);
}

static int devx_obj_cleanup(struct ib_uobject *uobject,
			    enum rdma_remove_reason why)
{
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];
	struct devx_obj *obj = uobject->object;
	int ret;

	if (obj->flags & DEVX_OBJ_FLAGS_INDIRECT_MKEY)
		devx_cleanup_mkey(obj);

	if (obj->flags & DEVX_OBJ_FLAGS_DCT)
		ret = mlx5_core_destroy_dct(obj->mdev, &obj->core_dct);
	else
		ret = mlx5_cmd_exec(obj->mdev, obj->dinbox, obj->dinlen, out,
				    sizeof(out));
	if (ib_is_destroy_retryable(ret, why, uobject))
		return ret;

	if (obj->flags & DEVX_OBJ_FLAGS_INDIRECT_MKEY) {
		struct mlx5_ib_dev *dev = to_mdev(uobject->context->device);

		call_srcu(&dev->mr_srcu, &obj->devx_mr.rcu,
			  devx_free_indirect_mkey);
		return ret;
	}

	kfree(obj);
	return ret;
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_OBJ_CREATE)(
	struct uverbs_attr_bundle *attrs)
{
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs, MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN);
	int cmd_out_len =  uverbs_attr_get_len(attrs,
					MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT);
	int cmd_in_len = uverbs_attr_get_len(attrs,
					MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN);
	void *cmd_out;
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, MLX5_IB_ATTR_DEVX_OBJ_CREATE_HANDLE);
	struct mlx5_ib_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct mlx5_ib_ucontext, ibucontext);
	struct mlx5_ib_dev *dev = to_mdev(c->ibucontext.device);
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];
	struct devx_obj *obj;
	int err;
	int uid;
	u32 obj_id;
	u16 opcode;

	uid = devx_get_uid(c, cmd_in);
	if (uid < 0)
		return uid;

	if (!devx_is_obj_create_cmd(cmd_in, &opcode))
		return -EINVAL;

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	obj = kzalloc(sizeof(struct devx_obj), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	MLX5_SET(general_obj_in_cmd_hdr, cmd_in, uid, uid);
	if (opcode == MLX5_CMD_OP_CREATE_MKEY) {
		err = devx_handle_mkey_create(dev, obj, cmd_in, cmd_in_len);
		if (err)
			goto obj_free;
	} else {
		devx_set_umem_valid(cmd_in);
	}

	if (opcode == MLX5_CMD_OP_CREATE_DCT) {
		obj->flags |= DEVX_OBJ_FLAGS_DCT;
		err = mlx5_core_create_dct(dev->mdev, &obj->core_dct,
					   cmd_in, cmd_in_len,
					   cmd_out, cmd_out_len);
	} else {
		err = mlx5_cmd_exec(dev->mdev, cmd_in,
				    cmd_in_len,
				    cmd_out, cmd_out_len);
	}

	if (err)
		goto obj_free;

	uobj->object = obj;
	obj->mdev = dev->mdev;
	devx_obj_build_destroy_cmd(cmd_in, cmd_out, obj->dinbox, &obj->dinlen,
				   &obj_id);
	WARN_ON(obj->dinlen > MLX5_MAX_DESTROY_INBOX_SIZE_DW * sizeof(u32));

	if (obj->flags & DEVX_OBJ_FLAGS_INDIRECT_MKEY) {
		err = devx_handle_mkey_indirect(obj, dev, cmd_in, cmd_out);
		if (err)
			goto obj_destroy;
	}

	err = uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT, cmd_out, cmd_out_len);
	if (err)
		goto err_copy;

	obj->obj_id = get_enc_obj_id(opcode, obj_id);
	return 0;

err_copy:
	if (obj->flags & DEVX_OBJ_FLAGS_INDIRECT_MKEY)
		devx_cleanup_mkey(obj);
obj_destroy:
	if (obj->flags & DEVX_OBJ_FLAGS_DCT)
		mlx5_core_destroy_dct(obj->mdev, &obj->core_dct);
	else
		mlx5_cmd_exec(obj->mdev, obj->dinbox, obj->dinlen, out,
			      sizeof(out));
obj_free:
	kfree(obj);
	return err;
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_OBJ_MODIFY)(
	struct uverbs_attr_bundle *attrs)
{
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN);
	int cmd_out_len = uverbs_attr_get_len(attrs,
					MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT);
	struct ib_uobject *uobj = uverbs_attr_get_uobject(attrs,
							  MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE);
	struct mlx5_ib_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct mlx5_ib_ucontext, ibucontext);
	struct mlx5_ib_dev *mdev = to_mdev(c->ibucontext.device);
	void *cmd_out;
	int err;
	int uid;

	uid = devx_get_uid(c, cmd_in);
	if (uid < 0)
		return uid;

	if (!devx_is_obj_modify_cmd(cmd_in))
		return -EINVAL;

	if (!devx_is_valid_obj_id(uobj, cmd_in))
		return -EINVAL;

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	MLX5_SET(general_obj_in_cmd_hdr, cmd_in, uid, uid);
	devx_set_umem_valid(cmd_in);

	err = mlx5_cmd_exec(mdev->mdev, cmd_in,
			    uverbs_attr_get_len(attrs, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN),
			    cmd_out, cmd_out_len);
	if (err)
		return err;

	return uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT,
			      cmd_out, cmd_out_len);
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_OBJ_QUERY)(
	struct uverbs_attr_bundle *attrs)
{
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN);
	int cmd_out_len = uverbs_attr_get_len(attrs,
					      MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT);
	struct ib_uobject *uobj = uverbs_attr_get_uobject(attrs,
							  MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE);
	struct mlx5_ib_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct mlx5_ib_ucontext, ibucontext);
	void *cmd_out;
	int err;
	int uid;
	struct mlx5_ib_dev *mdev = to_mdev(c->ibucontext.device);

	uid = devx_get_uid(c, cmd_in);
	if (uid < 0)
		return uid;

	if (!devx_is_obj_query_cmd(cmd_in))
		return -EINVAL;

	if (!devx_is_valid_obj_id(uobj, cmd_in))
		return -EINVAL;

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	MLX5_SET(general_obj_in_cmd_hdr, cmd_in, uid, uid);
	err = mlx5_cmd_exec(mdev->mdev, cmd_in,
			    uverbs_attr_get_len(attrs, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN),
			    cmd_out, cmd_out_len);
	if (err)
		return err;

	return uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT,
			      cmd_out, cmd_out_len);
}

struct devx_async_event_queue {
	spinlock_t		lock;
	wait_queue_head_t	poll_wait;
	struct list_head	event_list;
	atomic_t		bytes_in_use;
	u8			is_destroyed:1;
};

struct devx_async_cmd_event_file {
	struct ib_uobject		uobj;
	struct devx_async_event_queue	ev_queue;
	struct mlx5_async_ctx		async_ctx;
};

static void devx_init_event_queue(struct devx_async_event_queue *ev_queue)
{
	spin_lock_init(&ev_queue->lock);
	INIT_LIST_HEAD(&ev_queue->event_list);
	init_waitqueue_head(&ev_queue->poll_wait);
	atomic_set(&ev_queue->bytes_in_use, 0);
	ev_queue->is_destroyed = 0;
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_ASYNC_CMD_FD_ALLOC)(
	struct uverbs_attr_bundle *attrs)
{
	struct devx_async_cmd_event_file *ev_file;

	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, MLX5_IB_ATTR_DEVX_ASYNC_CMD_FD_ALLOC_HANDLE);
	struct mlx5_ib_dev *mdev = to_mdev(uobj->context->device);

	ev_file = container_of(uobj, struct devx_async_cmd_event_file,
			       uobj);
	devx_init_event_queue(&ev_file->ev_queue);
	mlx5_cmd_init_async_ctx(mdev->mdev, &ev_file->async_ctx);
	return 0;
}

static void devx_query_callback(int status, struct mlx5_async_work *context)
{
	struct devx_async_data *async_data =
		container_of(context, struct devx_async_data, cb_work);
	struct ib_uobject *fd_uobj = async_data->fd_uobj;
	struct devx_async_cmd_event_file *ev_file;
	struct devx_async_event_queue *ev_queue;
	unsigned long flags;

	ev_file = container_of(fd_uobj, struct devx_async_cmd_event_file,
			       uobj);
	ev_queue = &ev_file->ev_queue;

	spin_lock_irqsave(&ev_queue->lock, flags);
	list_add_tail(&async_data->list, &ev_queue->event_list);
	spin_unlock_irqrestore(&ev_queue->lock, flags);

	wake_up_interruptible(&ev_queue->poll_wait);
	fput(fd_uobj->object);
}

#define MAX_ASYNC_BYTES_IN_USE (1024 * 1024) /* 1MB */

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_OBJ_ASYNC_QUERY)(
	struct uverbs_attr_bundle *attrs)
{
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs,
				MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_CMD_IN);
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
				attrs,
				MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_HANDLE);
	u16 cmd_out_len;
	struct mlx5_ib_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct mlx5_ib_ucontext, ibucontext);
	struct ib_uobject *fd_uobj;
	int err;
	int uid;
	struct mlx5_ib_dev *mdev = to_mdev(c->ibucontext.device);
	struct devx_async_cmd_event_file *ev_file;
	struct devx_async_data *async_data;

	uid = devx_get_uid(c, cmd_in);
	if (uid < 0)
		return uid;

	if (!devx_is_obj_query_cmd(cmd_in))
		return -EINVAL;

	err = uverbs_get_const(&cmd_out_len, attrs,
			       MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_OUT_LEN);
	if (err)
		return err;

	if (!devx_is_valid_obj_id(uobj, cmd_in))
		return -EINVAL;

	fd_uobj = uverbs_attr_get_uobject(attrs,
				MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_FD);
	if (IS_ERR(fd_uobj))
		return PTR_ERR(fd_uobj);

	ev_file = container_of(fd_uobj, struct devx_async_cmd_event_file,
			       uobj);

	if (atomic_add_return(cmd_out_len, &ev_file->ev_queue.bytes_in_use) >
			MAX_ASYNC_BYTES_IN_USE) {
		atomic_sub(cmd_out_len, &ev_file->ev_queue.bytes_in_use);
		return -EAGAIN;
	}

	async_data = kvzalloc(struct_size(async_data, hdr.out_data,
					  cmd_out_len), GFP_KERNEL);
	if (!async_data) {
		err = -ENOMEM;
		goto sub_bytes;
	}

	err = uverbs_copy_from(&async_data->hdr.wr_id, attrs,
			       MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_WR_ID);
	if (err)
		goto free_async;

	async_data->cmd_out_len = cmd_out_len;
	async_data->mdev = mdev;
	async_data->fd_uobj = fd_uobj;

	get_file(fd_uobj->object);
	MLX5_SET(general_obj_in_cmd_hdr, cmd_in, uid, uid);
	err = mlx5_cmd_exec_cb(&ev_file->async_ctx, cmd_in,
		    uverbs_attr_get_len(attrs,
				MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_CMD_IN),
		    async_data->hdr.out_data,
		    async_data->cmd_out_len,
		    devx_query_callback, &async_data->cb_work);

	if (err)
		goto cb_err;

	return 0;

cb_err:
	fput(fd_uobj->object);
free_async:
	kvfree(async_data);
sub_bytes:
	atomic_sub(cmd_out_len, &ev_file->ev_queue.bytes_in_use);
	return err;
}

static int devx_umem_get(struct mlx5_ib_dev *dev, struct ib_ucontext *ucontext,
			 struct uverbs_attr_bundle *attrs,
			 struct devx_umem *obj)
{
	u64 addr;
	size_t size;
	u32 access;
	int npages;
	int err;
	u32 page_mask;

	if (uverbs_copy_from(&addr, attrs, MLX5_IB_ATTR_DEVX_UMEM_REG_ADDR) ||
	    uverbs_copy_from(&size, attrs, MLX5_IB_ATTR_DEVX_UMEM_REG_LEN))
		return -EFAULT;

	err = uverbs_get_flags32(&access, attrs,
				 MLX5_IB_ATTR_DEVX_UMEM_REG_ACCESS,
				 IB_ACCESS_LOCAL_WRITE |
				 IB_ACCESS_REMOTE_WRITE |
				 IB_ACCESS_REMOTE_READ);
	if (err)
		return err;

	err = ib_check_mr_access(access);
	if (err)
		return err;

	obj->umem = ib_umem_get(&attrs->driver_udata, addr, size, access, 0);
	if (IS_ERR(obj->umem))
		return PTR_ERR(obj->umem);

	mlx5_ib_cont_pages(obj->umem, obj->umem->address,
			   MLX5_MKEY_PAGE_SHIFT_MASK, &npages,
			   &obj->page_shift, &obj->ncont, NULL);

	if (!npages) {
		ib_umem_release(obj->umem);
		return -EINVAL;
	}

	page_mask = (1 << obj->page_shift) - 1;
	obj->page_offset = obj->umem->address & page_mask;

	return 0;
}

static int devx_umem_reg_cmd_alloc(struct uverbs_attr_bundle *attrs,
				   struct devx_umem *obj,
				   struct devx_umem_reg_cmd *cmd)
{
	cmd->inlen = MLX5_ST_SZ_BYTES(create_umem_in) +
		    (MLX5_ST_SZ_BYTES(mtt) * obj->ncont);
	cmd->in = uverbs_zalloc(attrs, cmd->inlen);
	return PTR_ERR_OR_ZERO(cmd->in);
}

static void devx_umem_reg_cmd_build(struct mlx5_ib_dev *dev,
				    struct devx_umem *obj,
				    struct devx_umem_reg_cmd *cmd)
{
	void *umem;
	__be64 *mtt;

	umem = MLX5_ADDR_OF(create_umem_in, cmd->in, umem);
	mtt = (__be64 *)MLX5_ADDR_OF(umem, umem, mtt);

	MLX5_SET(create_umem_in, cmd->in, opcode, MLX5_CMD_OP_CREATE_UMEM);
	MLX5_SET64(umem, umem, num_of_mtt, obj->ncont);
	MLX5_SET(umem, umem, log_page_size, obj->page_shift -
					    MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET(umem, umem, page_offset, obj->page_offset);
	mlx5_ib_populate_pas(dev, obj->umem, obj->page_shift, mtt,
			     (obj->umem->writable ? MLX5_IB_MTT_WRITE : 0) |
			     MLX5_IB_MTT_READ);
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_UMEM_REG)(
	struct uverbs_attr_bundle *attrs)
{
	struct devx_umem_reg_cmd cmd;
	struct devx_umem *obj;
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, MLX5_IB_ATTR_DEVX_UMEM_REG_HANDLE);
	u32 obj_id;
	struct mlx5_ib_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct mlx5_ib_ucontext, ibucontext);
	struct mlx5_ib_dev *dev = to_mdev(c->ibucontext.device);
	int err;

	if (!c->devx_uid)
		return -EINVAL;

	obj = kzalloc(sizeof(struct devx_umem), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	err = devx_umem_get(dev, &c->ibucontext, attrs, obj);
	if (err)
		goto err_obj_free;

	err = devx_umem_reg_cmd_alloc(attrs, obj, &cmd);
	if (err)
		goto err_umem_release;

	devx_umem_reg_cmd_build(dev, obj, &cmd);

	MLX5_SET(create_umem_in, cmd.in, uid, c->devx_uid);
	err = mlx5_cmd_exec(dev->mdev, cmd.in, cmd.inlen, cmd.out,
			    sizeof(cmd.out));
	if (err)
		goto err_umem_release;

	obj->mdev = dev->mdev;
	uobj->object = obj;
	devx_obj_build_destroy_cmd(cmd.in, cmd.out, obj->dinbox, &obj->dinlen, &obj_id);
	err = uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_UMEM_REG_OUT_ID, &obj_id, sizeof(obj_id));
	if (err)
		goto err_umem_destroy;

	return 0;

err_umem_destroy:
	mlx5_cmd_exec(obj->mdev, obj->dinbox, obj->dinlen, cmd.out, sizeof(cmd.out));
err_umem_release:
	ib_umem_release(obj->umem);
err_obj_free:
	kfree(obj);
	return err;
}

static int devx_umem_cleanup(struct ib_uobject *uobject,
			     enum rdma_remove_reason why)
{
	struct devx_umem *obj = uobject->object;
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];
	int err;

	err = mlx5_cmd_exec(obj->mdev, obj->dinbox, obj->dinlen, out, sizeof(out));
	if (ib_is_destroy_retryable(err, why, uobject))
		return err;

	ib_umem_release(obj->umem);
	kfree(obj);
	return 0;
}

static ssize_t devx_async_cmd_event_read(struct file *filp, char __user *buf,
					 size_t count, loff_t *pos)
{
	struct devx_async_cmd_event_file *comp_ev_file = filp->private_data;
	struct devx_async_event_queue *ev_queue = &comp_ev_file->ev_queue;
	struct devx_async_data *event;
	int ret = 0;
	size_t eventsz;

	spin_lock_irq(&ev_queue->lock);

	while (list_empty(&ev_queue->event_list)) {
		spin_unlock_irq(&ev_queue->lock);

		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		if (wait_event_interruptible(
			    ev_queue->poll_wait,
			    (!list_empty(&ev_queue->event_list) ||
			     ev_queue->is_destroyed))) {
			return -ERESTARTSYS;
		}

		if (list_empty(&ev_queue->event_list) &&
		    ev_queue->is_destroyed)
			return -EIO;

		spin_lock_irq(&ev_queue->lock);
	}

	event = list_entry(ev_queue->event_list.next,
			   struct devx_async_data, list);
	eventsz = event->cmd_out_len +
			sizeof(struct mlx5_ib_uapi_devx_async_cmd_hdr);

	if (eventsz > count) {
		spin_unlock_irq(&ev_queue->lock);
		return -ENOSPC;
	}

	list_del(ev_queue->event_list.next);
	spin_unlock_irq(&ev_queue->lock);

	if (copy_to_user(buf, &event->hdr, eventsz))
		ret = -EFAULT;
	else
		ret = eventsz;

	atomic_sub(event->cmd_out_len, &ev_queue->bytes_in_use);
	kvfree(event);
	return ret;
}

static int devx_async_cmd_event_close(struct inode *inode, struct file *filp)
{
	struct ib_uobject *uobj = filp->private_data;
	struct devx_async_cmd_event_file *comp_ev_file = container_of(
		uobj, struct devx_async_cmd_event_file, uobj);
	struct devx_async_data *entry, *tmp;

	spin_lock_irq(&comp_ev_file->ev_queue.lock);
	list_for_each_entry_safe(entry, tmp,
				 &comp_ev_file->ev_queue.event_list, list)
		kvfree(entry);
	spin_unlock_irq(&comp_ev_file->ev_queue.lock);

	uverbs_close_fd(filp);
	return 0;
}

static __poll_t devx_async_cmd_event_poll(struct file *filp,
					      struct poll_table_struct *wait)
{
	struct devx_async_cmd_event_file *comp_ev_file = filp->private_data;
	struct devx_async_event_queue *ev_queue = &comp_ev_file->ev_queue;
	__poll_t pollflags = 0;

	poll_wait(filp, &ev_queue->poll_wait, wait);

	spin_lock_irq(&ev_queue->lock);
	if (ev_queue->is_destroyed)
		pollflags = EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;
	else if (!list_empty(&ev_queue->event_list))
		pollflags = EPOLLIN | EPOLLRDNORM;
	spin_unlock_irq(&ev_queue->lock);

	return pollflags;
}

static const struct file_operations devx_async_cmd_event_fops = {
	.owner	 = THIS_MODULE,
	.read	 = devx_async_cmd_event_read,
	.poll    = devx_async_cmd_event_poll,
	.release = devx_async_cmd_event_close,
	.llseek	 = no_llseek,
};

static int devx_hot_unplug_async_cmd_event_file(struct ib_uobject *uobj,
						   enum rdma_remove_reason why)
{
	struct devx_async_cmd_event_file *comp_ev_file =
		container_of(uobj, struct devx_async_cmd_event_file,
			     uobj);
	struct devx_async_event_queue *ev_queue = &comp_ev_file->ev_queue;

	spin_lock_irq(&ev_queue->lock);
	ev_queue->is_destroyed = 1;
	spin_unlock_irq(&ev_queue->lock);

	if (why == RDMA_REMOVE_DRIVER_REMOVE)
		wake_up_interruptible(&ev_queue->poll_wait);

	mlx5_cmd_cleanup_async_ctx(&comp_ev_file->async_ctx);
	return 0;
};

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_UMEM_REG,
	UVERBS_ATTR_IDR(MLX5_IB_ATTR_DEVX_UMEM_REG_HANDLE,
			MLX5_IB_OBJECT_DEVX_UMEM,
			UVERBS_ACCESS_NEW,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(MLX5_IB_ATTR_DEVX_UMEM_REG_ADDR,
			   UVERBS_ATTR_TYPE(u64),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(MLX5_IB_ATTR_DEVX_UMEM_REG_LEN,
			   UVERBS_ATTR_TYPE(u64),
			   UA_MANDATORY),
	UVERBS_ATTR_FLAGS_IN(MLX5_IB_ATTR_DEVX_UMEM_REG_ACCESS,
			     enum ib_access_flags),
	UVERBS_ATTR_PTR_OUT(MLX5_IB_ATTR_DEVX_UMEM_REG_OUT_ID,
			    UVERBS_ATTR_TYPE(u32),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	MLX5_IB_METHOD_DEVX_UMEM_DEREG,
	UVERBS_ATTR_IDR(MLX5_IB_ATTR_DEVX_UMEM_DEREG_HANDLE,
			MLX5_IB_OBJECT_DEVX_UMEM,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_QUERY_EQN,
	UVERBS_ATTR_PTR_IN(MLX5_IB_ATTR_DEVX_QUERY_EQN_USER_VEC,
			   UVERBS_ATTR_TYPE(u32),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(MLX5_IB_ATTR_DEVX_QUERY_EQN_DEV_EQN,
			    UVERBS_ATTR_TYPE(u32),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_QUERY_UAR,
	UVERBS_ATTR_PTR_IN(MLX5_IB_ATTR_DEVX_QUERY_UAR_USER_IDX,
			   UVERBS_ATTR_TYPE(u32),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(MLX5_IB_ATTR_DEVX_QUERY_UAR_DEV_IDX,
			    UVERBS_ATTR_TYPE(u32),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_OTHER,
	UVERBS_ATTR_PTR_IN(
		MLX5_IB_ATTR_DEVX_OTHER_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_OBJ_CREATE,
	UVERBS_ATTR_IDR(MLX5_IB_ATTR_DEVX_OBJ_CREATE_HANDLE,
			MLX5_IB_OBJECT_DEVX_OBJ,
			UVERBS_ACCESS_NEW,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(
		MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	MLX5_IB_METHOD_DEVX_OBJ_DESTROY,
	UVERBS_ATTR_IDR(MLX5_IB_ATTR_DEVX_OBJ_DESTROY_HANDLE,
			MLX5_IB_OBJECT_DEVX_OBJ,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
	UVERBS_ATTR_IDR(MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE,
			UVERBS_IDR_ANY_OBJECT,
			UVERBS_ACCESS_WRITE,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(
		MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_OBJ_QUERY,
	UVERBS_ATTR_IDR(MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE,
			UVERBS_IDR_ANY_OBJECT,
			UVERBS_ACCESS_READ,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(
		MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_OBJ_ASYNC_QUERY,
	UVERBS_ATTR_IDR(MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE,
			UVERBS_IDR_ANY_OBJECT,
			UVERBS_ACCESS_READ,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(
		MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_CONST_IN(MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_OUT_LEN,
		u16, UA_MANDATORY),
	UVERBS_ATTR_FD(MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_FD,
		MLX5_IB_OBJECT_DEVX_ASYNC_CMD_FD,
		UVERBS_ACCESS_READ,
		UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(MLX5_IB_ATTR_DEVX_OBJ_QUERY_ASYNC_WR_ID,
		UVERBS_ATTR_TYPE(u64),
		UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(MLX5_IB_OBJECT_DEVX,
			      &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_OTHER),
			      &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_QUERY_UAR),
			      &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_QUERY_EQN));

DECLARE_UVERBS_NAMED_OBJECT(MLX5_IB_OBJECT_DEVX_OBJ,
			    UVERBS_TYPE_ALLOC_IDR(devx_obj_cleanup),
			    &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_OBJ_CREATE),
			    &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_OBJ_DESTROY),
			    &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_OBJ_MODIFY),
			    &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_OBJ_QUERY),
			    &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_OBJ_ASYNC_QUERY));

DECLARE_UVERBS_NAMED_OBJECT(MLX5_IB_OBJECT_DEVX_UMEM,
			    UVERBS_TYPE_ALLOC_IDR(devx_umem_cleanup),
			    &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_UMEM_REG),
			    &UVERBS_METHOD(MLX5_IB_METHOD_DEVX_UMEM_DEREG));


DECLARE_UVERBS_NAMED_METHOD(
	MLX5_IB_METHOD_DEVX_ASYNC_CMD_FD_ALLOC,
	UVERBS_ATTR_FD(MLX5_IB_ATTR_DEVX_ASYNC_CMD_FD_ALLOC_HANDLE,
			MLX5_IB_OBJECT_DEVX_ASYNC_CMD_FD,
			UVERBS_ACCESS_NEW,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(
	MLX5_IB_OBJECT_DEVX_ASYNC_CMD_FD,
	UVERBS_TYPE_ALLOC_FD(sizeof(struct devx_async_cmd_event_file),
			     devx_hot_unplug_async_cmd_event_file,
			     &devx_async_cmd_event_fops, "[devx_async_cmd]",
			     O_RDONLY),
	&UVERBS_METHOD(MLX5_IB_METHOD_DEVX_ASYNC_CMD_FD_ALLOC));

static bool devx_is_supported(struct ib_device *device)
{
	struct mlx5_ib_dev *dev = to_mdev(device);

	return !dev->rep && MLX5_CAP_GEN(dev->mdev, log_max_uctx);
}

const struct uapi_definition mlx5_ib_devx_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		MLX5_IB_OBJECT_DEVX,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		MLX5_IB_OBJECT_DEVX_OBJ,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		MLX5_IB_OBJECT_DEVX_UMEM,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		MLX5_IB_OBJECT_DEVX_ASYNC_CMD_FD,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	{},
};
