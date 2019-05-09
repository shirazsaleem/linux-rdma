/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2019, Intel Corporation. */

#ifndef IRDMA_TYPE_H
#define IRDMA_TYPE_H
#include "osdep.h"
#include "irdma.h"
#include "user.h"
#include "hmc.h"
#include "uda.h"

#ifndef CONFIG_DYNAMIC_DEBUG
enum irdma_debug_flag {
	IRDMA_DEBUG_NONE	= 0x00000000,
	IRDMA_DEBUG_ERR		= 0x00000001,
	IRDMA_DEBUG_INIT	= 0x00000002,
	IRDMA_DEBUG_DEV		= 0x00000004,
	IRDMA_DEBUG_CM		= 0x00000008,
	IRDMA_DEBUG_VERBS	= 0x00000010,
	IRDMA_DEBUG_PUDA	= 0x00000020,
	IRDMA_DEBUG_ILQ		= 0x00000040,
	IRDMA_DEBUG_IEQ		= 0x00000080,
	IRDMA_DEBUG_QP		= 0x00000100,
	IRDMA_DEBUG_CQ		= 0x00000200,
	IRDMA_DEBUG_MR		= 0x00000400,
	IRDMA_DEBUG_PBLE	= 0x00000800,
	IRDMA_DEBUG_WQE		= 0x00001000,
	IRDMA_DEBUG_AEQ		= 0x00002000,
	IRDMA_DEBUG_CQP		= 0x00004000,
	IRDMA_DEBUG_HMC		= 0x00008000,
	IRDMA_DEBUG_USER	= 0x00010000,
	IRDMA_DEBUG_VIRT	= 0x00020000,
	IRDMA_DEBUG_DCB		= 0x00040000,
	IRDMA_DEBUG_CQE		= 0x00800000,
	IRDMA_DEBUG_CLNT	= 0x01000000,
	IRDMA_DEBUG_WS		= 0x02000000,
	IRDMA_DEBUG_STATS	= 0x04000000,
	IRDMA_DEBUG_ALL		= 0xFFFFFFFF,
};
#else
#define IRDMA_DEBUG_ERR		"IRDMA_ERR"
#define IRDMA_DEBUG_INIT	"IRDMA_INIT"
#define IRDMA_DEBUG_DEV		"IRDMA_DEV"
#define IRDMA_DEBUG_CM		"IRDMA_CM"
#define IRDMA_DEBUG_VERBS	"IRDMA_VERBS"
#define IRDMA_DEBUG_PUDA	"IRDMA_PUDA"
#define IRDMA_DEBUG_ILQ		"IRDMA_ILQ"
#define IRDMA_DEBUG_IEQ		"IRDMA_IEQ"
#define IRDMA_DEBUG_QP		"IRDMA_QP"
#define IRDMA_DEBUG_CQ		"IRDMA_CQ"
#define IRDMA_DEBUG_MR		"IRDMA_MR"
#define IRDMA_DEBUG_PBLE	"IRDMA_PBLE"
#define IRDMA_DEBUG_WQE		"IRDMA_WQE"
#define IRDMA_DEBUG_AEQ		"IRDMA_AEQ"
#define IRDMA_DEBUG_CQP		"IRDMA_CQP"
#define IRDMA_DEBUG_HMC		"IRDMA_HMC"
#define IRDMA_DEBUG_USER	"IRDMA_USER"
#define IRDMA_DEBUG_VIRT	"IRDMA_VIRT"
#define IRDMA_DEBUG_DCB		"IRDMA_DCB"
#define	IRDMA_DEBUG_CQE		"IRDMA_CQE"
#define IRDMA_DEBUG_CLNT	"IRDMA_CLNT"
#define IRDMA_DEBUG_WS		"IRDMA_WS"
#define IRDMA_DEBUG_STATS	"IRDMA_DEBUG_STATS"
#endif

enum irdma_page_size {
	IRDMA_PAGE_SIZE_4K = 0,
	IRDMA_PAGE_SIZE_2M,
	IRDMA_PAGE_SIZE_1G,
};

enum irdma_hdrct_flags {
	DDP_LEN_FLAG  = 0x80,
	DDP_HDR_FLAG  = 0x40,
	RDMA_HDR_FLAG = 0x20,
};

enum irdma_term_layers {
	LAYER_RDMA = 0,
	LAYER_DDP  = 1,
	LAYER_MPA  = 2,
};

enum irdma_term_error_types {
	RDMAP_REMOTE_PROT = 1,
	RDMAP_REMOTE_OP   = 2,
	DDP_CATASTROPHIC  = 0,
	DDP_TAGGED_BUF    = 1,
	DDP_UNTAGGED_BUF  = 2,
	DDP_LLP		  = 3,
};

enum irdma_term_rdma_errors {
	RDMAP_INV_STAG		  = 0x00,
	RDMAP_INV_BOUNDS	  = 0x01,
	RDMAP_ACCESS		  = 0x02,
	RDMAP_UNASSOC_STAG	  = 0x03,
	RDMAP_TO_WRAP		  = 0x04,
	RDMAP_INV_RDMAP_VER       = 0x05,
	RDMAP_UNEXPECTED_OP       = 0x06,
	RDMAP_CATASTROPHIC_LOCAL  = 0x07,
	RDMAP_CATASTROPHIC_GLOBAL = 0x08,
	RDMAP_CANT_INV_STAG       = 0x09,
	RDMAP_UNSPECIFIED	  = 0xff,
};

enum irdma_term_ddp_errors {
	DDP_CATASTROPHIC_LOCAL      = 0x00,
	DDP_TAGGED_INV_STAG	    = 0x00,
	DDP_TAGGED_BOUNDS	    = 0x01,
	DDP_TAGGED_UNASSOC_STAG     = 0x02,
	DDP_TAGGED_TO_WRAP	    = 0x03,
	DDP_TAGGED_INV_DDP_VER      = 0x04,
	DDP_UNTAGGED_INV_QN	    = 0x01,
	DDP_UNTAGGED_INV_MSN_NO_BUF = 0x02,
	DDP_UNTAGGED_INV_MSN_RANGE  = 0x03,
	DDP_UNTAGGED_INV_MO	    = 0x04,
	DDP_UNTAGGED_INV_TOO_LONG   = 0x05,
	DDP_UNTAGGED_INV_DDP_VER    = 0x06,
};

enum irdma_term_mpa_errors {
	MPA_CLOSED  = 0x01,
	MPA_CRC     = 0x02,
	MPA_MARKER  = 0x03,
	MPA_REQ_RSP = 0x04,
};

enum irdma_flush_opcode {
	FLUSH_INVALID = 0,
	FLUSH_PROT_ERR,
	FLUSH_REM_ACCESS_ERR,
	FLUSH_LOC_QP_OP_ERR,
	FLUSH_REM_OP_ERR,
	FLUSH_LOC_LEN_ERR,
	FLUSH_GENERAL_ERR,
	FLUSH_FATAL_ERR,
};

enum irdma_term_eventtypes {
	TERM_EVENT_QP_FATAL,
	TERM_EVENT_QP_ACCESS_ERR,
};

enum irdma_hw_stats_index_32b {
	IRDMA_HW_STAT_INDEX_IP4RXDISCARD	= 0,
	IRDMA_HW_STAT_INDEX_IP4RXTRUNC		= 1,
	IRDMA_HW_STAT_INDEX_IP4TXNOROUTE	= 2,
	IRDMA_HW_STAT_INDEX_IP6RXDISCARD	= 3,
	IRDMA_HW_STAT_INDEX_IP6RXTRUNC		= 4,
	IRDMA_HW_STAT_INDEX_IP6TXNOROUTE	= 5,
	IRDMA_HW_STAT_INDEX_TCPRTXSEG		= 6,
	IRDMA_HW_STAT_INDEX_TCPRXOPTERR		= 7,
	IRDMA_HW_STAT_INDEX_TCPRXPROTOERR	= 8,
	IRDMA_HW_STAT_INDEX_MAX_32_GEN_1	= 9, /* Must be same value as next entry */
	IRDMA_HW_STAT_INDEX_RXVLANERR		= 9,
	IRDMA_HW_STAT_INDEX_RXRPCNPHANDLED	= 10,
	IRDMA_HW_STAT_INDEX_RXRPCNPIGNORED	= 11,
	IRDMA_HW_STAT_INDEX_TXNPCNPSENT		= 12,
	IRDMA_HW_STAT_INDEX_MAX_32, /* Must be last entry */
};

enum irdma_hw_stats_index_64b {
	IRDMA_HW_STAT_INDEX_IP4RXOCTS	= 0,
	IRDMA_HW_STAT_INDEX_IP4RXPKTS	= 1,
	IRDMA_HW_STAT_INDEX_IP4RXFRAGS	= 2,
	IRDMA_HW_STAT_INDEX_IP4RXMCPKTS	= 3,
	IRDMA_HW_STAT_INDEX_IP4TXOCTS	= 4,
	IRDMA_HW_STAT_INDEX_IP4TXPKTS	= 5,
	IRDMA_HW_STAT_INDEX_IP4TXFRAGS	= 6,
	IRDMA_HW_STAT_INDEX_IP4TXMCPKTS	= 7,
	IRDMA_HW_STAT_INDEX_IP6RXOCTS	= 8,
	IRDMA_HW_STAT_INDEX_IP6RXPKTS	= 9,
	IRDMA_HW_STAT_INDEX_IP6RXFRAGS	= 10,
	IRDMA_HW_STAT_INDEX_IP6RXMCPKTS	= 11,
	IRDMA_HW_STAT_INDEX_IP6TXOCTS	= 12,
	IRDMA_HW_STAT_INDEX_IP6TXPKTS	= 13,
	IRDMA_HW_STAT_INDEX_IP6TXFRAGS	= 14,
	IRDMA_HW_STAT_INDEX_IP6TXMCPKTS	= 15,
	IRDMA_HW_STAT_INDEX_TCPRXSEGS	= 16,
	IRDMA_HW_STAT_INDEX_TCPTXSEG	= 17,
	IRDMA_HW_STAT_INDEX_RDMARXRDS	= 18,
	IRDMA_HW_STAT_INDEX_RDMARXSNDS	= 19,
	IRDMA_HW_STAT_INDEX_RDMARXWRS	= 20,
	IRDMA_HW_STAT_INDEX_RDMATXRDS	= 21,
	IRDMA_HW_STAT_INDEX_RDMATXSNDS	= 22,
	IRDMA_HW_STAT_INDEX_RDMATXWRS	= 23,
	IRDMA_HW_STAT_INDEX_RDMAVBND	= 24,
	IRDMA_HW_STAT_INDEX_RDMAVINV	= 25,
	IRDMA_HW_STAT_INDEX_MAX_64_GEN_1 = 26, /* Must be same value as next entry */
	IRDMA_HW_STAT_INDEX_IP4RXMCOCTS	= 26,
	IRDMA_HW_STAT_INDEX_IP4TXMCOCTS	= 27,
	IRDMA_HW_STAT_INDEX_IP6RXMCOCTS	= 28,
	IRDMA_HW_STAT_INDEX_IP6TXMCOCTS	= 29,
	IRDMA_HW_STAT_INDEX_UDPRXPKTS	= 30,
	IRDMA_HW_STAT_INDEX_UDPTXPKTS	= 31,
	IRDMA_HW_STAT_INDEX_RXNPECNMARKEDPKTS = 32,
	IRDMA_HW_STAT_INDEX_MAX_64, /* Must be last entry */
};

enum irdma_feature_type {
	IRDMA_FEATURE_FW_INFO = 0,
	IRDMA_HW_VERSION_INFO,
	IRDMA_MAX_FEATURES, /* Must be last entry */
};

enum irdma_sched_prio_type {
	IRDMA_PRIO_WEIGHTED_RR     = 1,
	IRDMA_PRIO_STRICT	   = 2,
	IRDMA_PRIO_WEIGHTED_STRICT = 3,
};

enum irdma_vm_vf_type {
	IRDMA_VF_TYPE = 0,
	IRDMA_VM_TYPE,
	IRDMA_PF_TYPE,
};

enum irdma_cqp_hmc_profile {
	IRDMA_HMC_PROFILE_DEFAULT  = 1,
	IRDMA_HMC_PROFILE_FAVOR_VF = 2,
	IRDMA_HMC_PROFILE_EQUAL    = 3,
};

enum irdma_quad_entry_type {
	IRDMA_QHASH_TYPE_TCP_ESTABLISHED = 1,
	IRDMA_QHASH_TYPE_TCP_SYN,
	IRDMA_QHASH_TYPE_UDP_UNICAST,
	IRDMA_QHASH_TYPE_UDP_MCAST,
	IRDMA_QHASH_TYPE_ROCE_MCAST,
	IRDMA_QHASH_TYPE_ROCEV2_HW,
};

enum irdma_quad_hash_manage_type {
	IRDMA_QHASH_MANAGE_TYPE_DELETE = 0,
	IRDMA_QHASH_MANAGE_TYPE_ADD,
	IRDMA_QHASH_MANAGE_TYPE_MODIFY,
};

enum irdma_syn_rst_handling {
	IRDMA_SYN_RST_HANDLING_HW_TCP_SECURE = 0,
	IRDMA_SYN_RST_HANDLING_HW_TCP,
	IRDMA_SYN_RST_HANDLING_FW_TCP_SECURE,
	IRDMA_SYN_RST_HANDLING_FW_TCP,
};

struct irdma_sc_dev;
struct irdma_vsi_pestat;
struct irdma_irq_ops;
struct irdma_cqp_ops;
struct irdma_ccq_ops;
struct irdma_ceq_ops;
struct irdma_aeq_ops;
struct irdma_mr_ops;
struct irdma_cqp_misc_ops;
struct irdma_pd_ops;
struct irdma_ah_ops;
struct irdma_priv_qp_ops;
struct irdma_priv_cq_ops;
struct irdma_hmc_ops;

struct irdma_cqp_init_info {
	u64 cqp_compl_ctx;
	u64 host_ctx_pa;
	u64 sq_pa;
	struct irdma_sc_dev *dev;
	struct irdma_cqp_quanta *sq;
	__le64 *host_ctx;
	u64 *scratch_array;
	u32 sq_size;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	bool en_datacenter_tcp;
	u8 hmc_profile;
	u8 ena_vf_count;
	u8 ceqs_per_vf;
	bool disable_packed;
	bool rocev2_rto_policy;
	enum irdma_protocol_used protocol_used;
};

struct irdma_terminate_hdr {
	u8 layer_etype;
	u8 error_code;
	u8 hdrct;
	u8 rsvd;
};

struct irdma_cqp_sq_wqe {
	__le64 buf[IRDMA_CQP_WQE_SIZE];
};

struct irdma_sc_aeqe {
	__le64 buf[IRDMA_AEQE_SIZE];
};

struct irdma_ceqe {
	__le64 buf[IRDMA_CEQE_SIZE];
};

struct irdma_cqp_ctx {
	__le64 buf[IRDMA_CQP_CTX_SIZE];
};

struct irdma_cq_shadow_area {
	__le64 buf[IRDMA_SHADOW_AREA_SIZE];
};

struct irdma_dev_hw_stats_offsets {
	u32 stats_offset_32[IRDMA_HW_STAT_INDEX_MAX_32];
	u32 stats_offset_64[IRDMA_HW_STAT_INDEX_MAX_64];
};

struct irdma_dev_hw_stats {
	u64 stats_val_32[IRDMA_HW_STAT_INDEX_MAX_32];
	u64 stats_val_64[IRDMA_HW_STAT_INDEX_MAX_64];
};

struct irdma_gather_stats {
	u32 rsvd1;
	u32 rxvlanerr;
	u64 ip4rxocts;
	u64 ip4rxpkts;
	u32 ip4rxtrunc;
	u32 ip4rxdiscard;
	u64 ip4rxfrags;
	u64 ip4rxmcocts;
	u64 ip4rxmcpkts;
	u64 ip6rxocts;
	u64 ip6rxpkts;
	u32 ip6rxtrunc;
	u32 ip6rxdiscard;
	u64 ip6rxfrags;
	u64 ip6rxmcocts;
	u64 ip6rxmcpkts;
	u64 ip4txocts;
	u64 ip4txpkts;
	u64 ip4txfrag;
	u64 ip4txmcocts;
	u64 ip4txmcpkts;
	u64 ip6txocts;
	u64 ip6txpkts;
	u64 ip6txfrags;
	u64 ip6txmcocts;
	u64 ip6txmcpkts;
	u32 ip6txnoroute;
	u32 ip4txnoroute;
	u64 tcprxsegs;
	u32 tcprxprotoerr;
	u32 tcprxopterr;
	u64 tcptxsegs;
	u32 rsvd2;
	u32 tcprtxseg;
	u64 udprxpkts;
	u64 udptxpkts;
	u64 rdmarxwrs;
	u64 rdmarxrds;
	u64 rdmarxsnds;
	u64 rdmatxwrs;
	u64 rdmatxrds;
	u64 rdmatxsnds;
	u64 rdmavbn;
	u64 rdmavinv;
	u64 rxnpecnmrkpkts;
	u32 rxrpcnphandled;
	u32 rxrpcnpignored;
	u32 txnpcnpsent;
	u32 rsvd3[88];
};

struct irdma_stats_gather_info {
	bool use_hmc_fcn_index;
	bool use_stats_inst;
	u8 hmc_fcn_index;
	u8 stats_inst_index;
	struct irdma_dma_mem stats_buff_mem;
	struct irdma_gather_stats *gather_stats;
	struct irdma_gather_stats *last_gather_stats;
};

struct irdma_vsi_pestat {
	struct irdma_hw *hw;
	struct irdma_dev_hw_stats hw_stats;
	struct irdma_stats_gather_info gather_info;
	struct timer_list stats_timer;
	struct irdma_sc_vsi *vsi;
	struct irdma_dev_hw_stats last_hw_stats;
	spinlock_t lock; /* rdma stats lock */
};

struct irdma_hw {
	u8 __iomem *hw_addr;
	struct pci_dev *pdev;
	struct irdma_hmc_info hmc;
};

struct irdma_pfpdu {
	struct list_head rxlist;
	u32 rcv_nxt;
	u32 fps;
	u32 max_fpdu_data;
	u32 nextseqnum;
	bool mode;
	bool mpa_crc_err;
	u64 total_ieq_bufs;
	u64 fpdu_processed;
	u64 bad_seq_num;
	u64 crc_err;
	u64 no_tx_bufs;
	u64 tx_err;
	u64 out_of_order;
	u64 pmode_count;
	struct irdma_sc_ah *ah;
	struct irdma_puda_buf *ah_buf;
	spinlock_t lock; /* fpdu processing lock */
	struct irdma_puda_buf *lastrcv_buf;
};

struct irdma_sc_pd {
	struct irdma_sc_dev *dev;
	u32 pd_id;
	int abi_ver;
};

struct irdma_cqp_quanta {
	__le64 elem[IRDMA_CQP_WQE_SIZE];
};

struct irdma_sc_cqp {
	u32 size;
	u64 sq_pa;
	u64 host_ctx_pa;
	void *back_cqp;
	struct irdma_sc_dev *dev;
	enum irdma_status_code (*process_cqp_sds)(struct irdma_sc_dev *dev,
						  struct irdma_update_sds_info *info);
	struct irdma_dma_mem sdbuf;
	struct irdma_ring sq_ring;
	struct irdma_cqp_quanta *sq_base;
	__le64 *host_ctx;
	u64 *scratch_array;
	u32 cqp_id;
	u32 sq_size;
	u32 hw_sq_size;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 polarity;
	u8 hmc_profile;
	u8 ena_vf_count;
	u8 timeout_count;
	u8 ceqs_per_vf;
	bool en_datacenter_tcp;
	bool disable_packed;
	bool rocev2_rto_policy;
	enum irdma_protocol_used protocol_used;
};

struct irdma_sc_aeq {
	u32 size;
	u64 aeq_elem_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_aeqe *aeqe_base;
	void *pbl_list;
	u32 elem_cnt;
	struct irdma_ring aeq_ring;
	bool virtual_map;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	u8 polarity;
};

struct irdma_sc_ceq {
	u32 size;
	u64 ceq_elem_pa;
	struct irdma_sc_dev *dev;
	struct irdma_ceqe *ceqe_base;
	void *pbl_list;
	u32 ceq_id;
	u32 elem_cnt;
	struct irdma_ring ceq_ring;
	bool virtual_map;
	u8 pbl_chunk_size;
	bool tph_en;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	u8 polarity;
	bool itr_no_expire;
	struct irdma_sc_vsi *vsi;
	struct irdma_sc_cq **reg_cq;
	u32 reg_cq_size;
	spinlock_t req_cq_lock; /* protect access to reg_cq array */
};

struct irdma_sc_cq {
	struct irdma_cq_uk cq_uk;
	u64 cq_pa;
	u64 shadow_area_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_vsi *vsi;
	void *pbl_list;
	void *back_cq;
	u32 ceq_id;
	u32 shadow_read_threshold;
	bool ceqe_mask;
	bool virtual_map;
	u8 pbl_chunk_size;
	u8 cq_type;
	bool ceq_id_valid;
	bool tph_en;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	bool check_overflow;
};

struct irdma_sc_qp {
	struct irdma_qp_uk qp_uk;
	u64 sq_pa;
	u64 rq_pa;
	u64 hw_host_ctx_pa;
	u64 shadow_area_pa;
	u64 q2_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_vsi *vsi;
	struct irdma_sc_pd *pd;
	__le64 *hw_host_ctx;
	void *llp_stream_handle;
	struct irdma_pfpdu pfpdu;
	u32 ieq_qp;
	u8 *q2_buf;
	u64 qp_compl_ctx;
	u16 qs_handle;
	u16 push_idx;
	u8 sq_tph_val;
	u8 rq_tph_val;
	u8 qp_state;
	u8 qp_type;
	u8 hw_sq_size;
	u8 hw_rq_size;
	u8 src_mac_addr_idx;
	bool sq_tph_en;
	bool rq_tph_en;
	bool rcv_tph_en;
	bool xmit_tph_en;
	bool virtual_map;
	bool flush_sq;
	bool flush_rq;
	u8 user_pri;
	struct list_head list;
	bool on_qoslist;
	bool sq_flush;
	enum irdma_flush_opcode flush_code;
	enum irdma_term_eventtypes eventtype;
	u8 term_flags;
};

struct irdma_stats_inst_info {
	bool use_hmc_fcn_index;
	u8 hmc_fn_id;
	u8 stats_idx;
};

struct irdma_up_info {
	u8 map[8];
	u8 cnp_up_override;
	u8 hmc_fcn_idx;
	bool use_vlan;
	bool use_cnp_up_override;
};

#define IRDMA_MAX_WS_NODES	0x3FF
#define IRDMA_WS_NODE_INVALID	0xFFFF

struct irdma_ws_node_info {
	u16 id;
	u16 vsi;
	u16 parent_id;
	u16 qs_handle;
	bool type_leaf;
	bool enable;
	u8 prio_type;
	u8 tc;
	u8 weight;
};

struct irdma_hmc_fpm_misc {
	u32 max_ceqs;
	u32 max_sds;
	u32 xf_block_size;
	u32 q1_block_size;
	u32 ht_multiplier;
	u32 timer_bucket;
	u32 rrf_block_size;
	u32 ooiscf_block_size;
};

#define IRDMA_LEAF_DEFAULT_REL_BW		64
#define IRDMA_PARENT_DEFAULT_REL_BW		1

struct irdma_qos {
	struct list_head qplist;
	spinlock_t lock; /* protect qos list */
	u64 lan_qos_handle;
	u32 l2_sched_node_id;
	u16 qs_handle;
	u8 traffic_class;
	u8 rel_bw;
	u8 prio_type;
};

#define IRDMA_INVALID_FCN_ID 0xff
struct irdma_sc_vsi {
	u16 vsi_idx;
	struct irdma_sc_dev *dev;
	void *back_vsi;
	u32 ilq_count;
	struct irdma_virt_mem ilq_mem;
	struct irdma_puda_rsrc *ilq;
	u32 ieq_count;
	struct irdma_virt_mem ieq_mem;
	struct irdma_puda_rsrc *ieq;
	u32 exception_lan_q;
	u16 mtu;
	u16 vm_id;
	u8 fcn_id;
	enum irdma_vm_vf_type vm_vf_type;
	bool stats_fcn_id_alloc;
	struct irdma_qos qos[IRDMA_MAX_USER_PRIORITY];
	struct irdma_vsi_pestat *pestat;
	atomic_t qp_suspend_reqs;
	bool tc_change_pending;
	u8 qos_rel_bw;
	u8 qos_prio_type;
};

struct irdma_sc_dev {
	struct list_head cqp_cmd_head; /* head of the CQP command list */
	spinlock_t cqp_lock; /* protect CQP list access */
	struct irdma_dev_uk dev_uk;
	bool fcn_id_array[IRDMA_MAX_STATS_COUNT];
	struct irdma_dma_mem vf_fpm_query_buf[IRDMA_MAX_PE_ENA_VF_COUNT];
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le64 *fpm_query_buf;
	__le64 *fpm_commit_buf;
	void *back_dev;
	struct irdma_hw *hw;
	u8 __iomem *db_addr;
	u32 __iomem *wqe_alloc_db;
	u32 __iomem *cq_arm_db;
	u32 __iomem *aeq_alloc_db;
	u32 __iomem *cqp_db;
	u32 __iomem *cq_ack_db;
	u32 __iomem *ceq_itr_mask_db;
	u32 __iomem *aeq_itr_mask_db;
	u32 hw_regs[IRDMA_MAX_REGS];
	u64 hw_masks[IRDMA_MAX_MASKS];
	u64 hw_shifts[IRDMA_MAX_SHIFTS];
	u64 hw_stats_regs_32[IRDMA_HW_STAT_INDEX_MAX_32];
	u64 hw_stats_regs_64[IRDMA_HW_STAT_INDEX_MAX_64];
	u64 feature_info[IRDMA_MAX_FEATURES];
	u64 cqp_cmd_stats[IRDMA_OP_SIZE_CQP_STAT_ARRAY];
	struct irdma_hw_attrs hw_attrs;
	struct irdma_hmc_info *hmc_info;
	struct irdma_vfdev *vf_dev[IRDMA_MAX_PE_ENA_VF_COUNT];
	struct irdma_sc_cqp *cqp;
	struct irdma_sc_aeq *aeq;
	struct irdma_sc_ceq *ceq[IRDMA_CEQ_MAX_COUNT];
	struct irdma_sc_cq *ccq;
	struct irdma_irq_ops *irq_ops;
	struct irdma_cqp_ops *cqp_ops;
	struct irdma_ccq_ops *ccq_ops;
	struct irdma_ceq_ops *ceq_ops;
	struct irdma_aeq_ops *aeq_ops;
	struct irdma_pd_ops *iw_pd_ops;
	struct irdma_ah_ops *iw_ah_ops;
	struct irdma_priv_qp_ops *iw_priv_qp_ops;
	struct irdma_priv_cq_ops *iw_priv_cq_ops;
	struct irdma_mr_ops *mr_ops;
	struct irdma_cqp_misc_ops *cqp_misc_ops;
	struct irdma_hmc_ops *hmc_ops;
	struct irdma_uda_ops *iw_uda_ops;
	struct irdma_hmc_fpm_misc hmc_fpm_misc;
	struct irdma_ws_node *ws_tree_root;
	struct mutex ws_mutex; /* ws tree mutex */
#ifndef CONFIG_DYNAMIC_DEBUG
	u32 debug_mask;
#endif
	u16 num_vfs;
	u8 hmc_fn_id;
	u8 vf_id;
	bool is_pf;
	bool vchnl_up;
	bool ceq_valid;
	u8 pci_rev;
	enum irdma_status_code (*ws_add)(struct irdma_sc_vsi *vsi, u8 user_pri);
	void (*ws_remove)(struct irdma_sc_vsi *vsi, u8 user_pri);
};

struct irdma_modify_cq_info {
	u64 cq_pa;
	struct irdma_cqe *cq_base;
	u32 ceq_id;
	u32 cq_size;
	u32 shadow_read_threshold;
	bool virtual_map;
	u8 pbl_chunk_size;
	bool check_overflow;
	bool cq_resize;
	u32 first_pm_pbl_idx;
	bool ceq_valid;
};

struct irdma_create_qp_info {
	bool ord_valid;
	bool tcp_ctx_valid;
	bool cq_num_valid;
	bool arp_cache_idx_valid;
	bool mac_valid;
	bool force_lpb;
	u8 next_iwarp_state;
};

struct irdma_modify_qp_info {
	u64 rx_win0;
	u64 rx_win1;
	u16 new_mss;
	u8 next_iwarp_state;
	u8 curr_iwarp_state;
	u8 termlen;
	bool ord_valid;
	bool tcp_ctx_valid;
	bool udp_ctx_valid;
	bool cq_num_valid;
	bool arp_cache_idx_valid;
	bool reset_tcp_conn;
	bool remove_hash_idx;
	bool dont_send_term;
	bool dont_send_fin;
	bool cached_var_valid;
	bool mss_change;
	bool force_lpb;
	bool mac_valid;
};

struct irdma_ccq_cqe_info {
	struct irdma_sc_cqp *cqp;
	u64 scratch;
	u32 op_ret_val;
	u16 maj_err_code;
	u16 min_err_code;
	u8 op_code;
	bool error;
};

struct irdma_dcb_app_info {
	u8 priority;
	u8 selector;
	u16 prot_id;
};

struct irdma_qos_tc_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

struct irdma_l2params {
	struct irdma_qos_tc_info tc_info[IRDMA_MAX_USER_PRIORITY];
	struct irdma_dcb_app_info apps[IRDMA_MAX_APPS];
	u32 num_apps;
	u16 qs_handle_list[IRDMA_MAX_USER_PRIORITY];
	u16 mtu;
	u8 up2tc[IRDMA_MAX_USER_PRIORITY];
	u8 num_tc;
	u8 vsi_rel_bw;
	u8 vsi_prio_type;
	bool mtu_changed;
	bool tc_changed;
};

struct irdma_vsi_init_info {
	struct irdma_sc_dev *dev;
	void *back_vsi;
	struct irdma_l2params *params;
	u16 exception_lan_q;
	u16 pf_data_vsi_num;
	enum irdma_vm_vf_type vm_vf_type;
	u16 vm_id;
};

struct irdma_vsi_stats_info {
	struct irdma_vsi_pestat *pestat;
	u8 fcn_id;
	bool alloc_fcn_id;
};

struct irdma_device_init_info {
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le64 *fpm_query_buf;
	__le64 *fpm_commit_buf;
	struct irdma_hw *hw;
	void __iomem *bar0;
	enum irdma_status_code (*vchnl_send)(struct irdma_sc_dev *dev,
					     u32 vf_id, u8 *msg, u16 len);
	void (*init_hw)(struct irdma_sc_dev *dev);
	u8 hmc_fn_id;
	bool is_pf;
#ifndef CONFIG_DYNAMIC_DEBUG
	u32 debug_mask;
#endif
};

struct irdma_ceq_init_info {
	u64 ceqe_pa;
	struct irdma_sc_dev *dev;
	u64 *ceqe_base;
	void *pbl_list;
	u32 elem_cnt;
	u32 ceq_id;
	bool virtual_map;
	u8 pbl_chunk_size;
	bool tph_en;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	bool itr_no_expire;
	struct irdma_sc_vsi *vsi;
	struct irdma_sc_cq **reg_cq;
	u32 reg_cq_idx;
};

struct irdma_aeq_init_info {
	u64 aeq_elem_pa;
	struct irdma_sc_dev *dev;
	u32 *aeqe_base;
	void *pbl_list;
	u32 elem_cnt;
	bool virtual_map;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
};

struct irdma_ccq_init_info {
	u64 cq_pa;
	u64 shadow_area_pa;
	struct irdma_sc_dev *dev;
	struct irdma_cqe *cq_base;
	__le64 *shadow_area;
	void *pbl_list;
	u32 num_elem;
	u32 ceq_id;
	u32 shadow_read_threshold;
	bool ceqe_mask;
	bool ceq_id_valid;
	bool tph_en;
	u8 tph_val;
	bool avoid_mem_cflct;
	bool virtual_map;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	struct irdma_sc_vsi *vsi;
};

struct irdma_udp_offload_info {
	bool ipv4;
	bool insert_vlan_tag;
	u8 ttl;
	u8 tos;
	u16 src_port;
	u16 dst_port;
	u32 dest_ip_addr0;
	u32 dest_ip_addr1;
	u32 dest_ip_addr2;
	u32 dest_ip_addr3;
	u32 snd_mss;
	u16 vlan_tag;
	u16 arp_idx;
	u32 flow_label;
	u8 udp_state;
	u32 psn_nxt;
	u32 lsn;
	u32 epsn;
	u32 psn_max;
	u32 psn_una;
	u32 local_ipaddr0;
	u32 local_ipaddr1;
	u32 local_ipaddr2;
	u32 local_ipaddr3;
	u32 cwnd;
	u8 rexmit_thresh;
	u8 rnr_nak_thresh;
};

struct irdma_roce_offload_info {
	u16 p_key;
	u16 err_rq_idx;
	u32 qkey;
	u32 dest_qp;
	u32 local_qp;
	bool is_qp1;
	bool udprivcq_en;
	u8 roce_tver;
	u8 ack_credits;
	u8 err_rq_idx_valid;
	u32 pd_id;
	u8 ord_size;
	u8 ird_size;
	bool dcqcn_en;
	bool rcv_no_icrc;
	bool wr_rdresp_en;
	bool bind_en;
	bool fast_reg_en;
	bool priv_mode_en;
	bool rd_en;
	bool timely_en;
	u16 t_high;
	u16 t_low;
	bool use_stats_inst;
	u8 last_byte_sent;
	u8 mac_addr[ETH_ALEN];
	bool ecn_en;
	bool dctcp_en;
	bool fw_cc_enable;
};

struct irdma_iwarp_offload_info {
	u16 rcv_mark_offset;
	u16 snd_mark_offset;
	u8 ddp_ver;
	u8 rdmap_ver;
	bool snd_mark_en;
	bool rcv_mark_en;
	bool ib_rd_en;
	u8 iwarp_mode;
	bool align_hdrs;
	bool rcv_no_mpa_crc;

	bool err_rq_idx_valid;
	u16 err_rq_idx;
	u32 pd_id;
	u8 ord_size;
	u8 ird_size;
	bool wr_rdresp_en;
	bool bind_en;
	bool fast_reg_en;
	bool priv_mode_en;
	bool rd_en;
	bool timely_en;
	u16 t_high;
	u16 t_low;
	bool use_stats_inst;
	u8 last_byte_sent;
	u8 mac_addr[ETH_ALEN];
	bool ecn_en;
	bool dctcp_en;
};

struct irdma_tcp_offload_info {
	bool ipv4;
	bool no_nagle;
	bool insert_vlan_tag;
	bool time_stamp;
	u8 cwnd_inc_limit;
	bool drop_ooo_seg;
	u8 dup_ack_thresh;
	u8 ttl;
	u8 src_mac_addr_idx;
	bool avoid_stretch_ack;
	u8 tos;
	u16 src_port;
	u16 dst_port;
	u32 dest_ip_addr0;
	u32 dest_ip_addr1;
	u32 dest_ip_addr2;
	u32 dest_ip_addr3;
	u32 snd_mss;
	u16 syn_rst_handling;
	u16 vlan_tag;
	u16 arp_idx;
	u32 flow_label;
	bool wscale;
	u8 tcp_state;
	u8 snd_wscale;
	u8 rcv_wscale;
	u32 time_stamp_recent;
	u32 time_stamp_age;
	u32 snd_nxt;
	u32 snd_wnd;
	u32 rcv_nxt;
	u32 rcv_wnd;
	u32 snd_max;
	u32 snd_una;
	u32 srtt;
	u32 rtt_var;
	u32 ss_thresh;
	u32 cwnd;
	u32 snd_wl1;
	u32 snd_wl2;
	u32 max_snd_window;
	u8 rexmit_thresh;
	u32 local_ipaddr0;
	u32 local_ipaddr1;
	u32 local_ipaddr2;
	u32 local_ipaddr3;
	bool ignore_tcp_opt;
	bool ignore_tcp_uns_opt;
};

struct irdma_qp_host_ctx_info {
	u64 qp_compl_ctx;
	union {
		struct irdma_tcp_offload_info *tcp_info;
		struct irdma_udp_offload_info *udp_info;
	};
	union {
		struct irdma_iwarp_offload_info *iwarp_info;
		struct irdma_roce_offload_info *roce_info;
	};
	u32 send_cq_num;
	u32 rcv_cq_num;
	u32 rem_endpoint_idx;
	u16 push_idx;
	u8 stats_idx;
	bool push_mode_en;
	bool tcp_info_valid;
	bool iwarp_info_valid;
	bool stats_idx_valid;
	bool add_to_qoslist;
	u8 user_pri;
};

struct irdma_aeqe_info {
	u64 compl_ctx;
	u32 qp_cq_id;
	u16 ae_id;
	u16 wqe_idx;
	u8 tcp_state;
	u8 iwarp_state;
	bool qp;
	bool cq;
	bool sq;
	bool in_rdrsp_wr;
	bool out_rdrsp;
	u8 q2_data_written;
	bool aeqe_overflow;
};

struct irdma_allocate_stag_info {
	u64 total_len;
	u64 first_pm_pbl_idx;
	u32 chunk_size;
	u32 stag_idx;
	u32 page_size;
	u32 pd_id;
	u16 access_rights;
	bool remote_access;
	bool use_hmc_fcn_index;
	u8 hmc_fcn_index;
	bool use_pf_rid;
};

struct irdma_mw_alloc_info {
	u32 mw_stag_index;
	u32 page_size;
	u32 pd_id;
	bool remote_access;
	bool mw_wide;
	bool mw1_bind_dont_vldt_key;
};

struct irdma_reg_ns_stag_info {
	u64 reg_addr_pa;
	u64 fbo;
	void *va;
	u64 total_len;
	u32 page_size;
	u32 chunk_size;
	u32 first_pm_pbl_index;
	enum irdma_addressing_type addr_type;
	irdma_stag_index stag_idx;
	u16 access_rights;
	u32 pd_id;
	irdma_stag_key stag_key;
	bool use_hmc_fcn_index;
	u8 hmc_fcn_index;
	bool use_pf_rid;
};

struct irdma_fast_reg_stag_info {
	u64 wr_id;
	u64 reg_addr_pa;
	u64 fbo;
	void *va;
	u64 total_len;
	u32 page_size;
	u32 chunk_size;
	u32 first_pm_pbl_index;
	enum irdma_addressing_type addr_type;
	irdma_stag_index stag_idx;
	u16 access_rights;
	u32 pd_id;
	irdma_stag_key stag_key;
	bool local_fence;
	bool read_fence;
	bool signaled;
	bool push_wqe;
	bool use_hmc_fcn_index;
	u8 hmc_fcn_index;
	bool use_pf_rid;
	bool defer_flag;
};

struct irdma_dealloc_stag_info {
	u32 stag_idx;
	u32 pd_id;
	bool mr;
	bool dealloc_pbl;
};

struct irdma_register_shared_stag {
	void *va;
	enum irdma_addressing_type addr_type;
	irdma_stag_index new_stag_idx;
	irdma_stag_index parent_stag_idx;
	u32 access_rights;
	u32 pd_id;
	irdma_stag_key new_stag_key;
};

struct irdma_qp_init_info {
	struct irdma_qp_uk_init_info qp_uk_init_info;
	struct irdma_sc_pd *pd;
	struct irdma_sc_vsi *vsi;
	__le64 *host_ctx;
	u8 *q2;
	u64 sq_pa;
	u64 rq_pa;
	u64 host_ctx_pa;
	u64 q2_pa;
	u64 shadow_area_pa;
	u8 sq_tph_val;
	u8 rq_tph_val;
	u8 type;
	bool sq_tph_en;
	bool rq_tph_en;
	bool rcv_tph_en;
	bool xmit_tph_en;
	bool virtual_map;
};

struct irdma_cq_init_info {
	struct irdma_sc_dev *dev;
	u64 cq_base_pa;
	u64 shadow_area_pa;
	u32 ceq_id;
	u32 shadow_read_threshold;
	bool virtual_map;
	bool ceqe_mask;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	bool ceq_id_valid;
	bool tph_en;
	u8 tph_val;
	u8 type;
	struct irdma_cq_uk_init_info cq_uk_init_info;
	struct irdma_sc_vsi *vsi;
};

struct irdma_upload_context_info {
	u64 buf_pa;
	bool freeze_qp;
	bool raw_format;
	u32 qp_id;
	u8 qp_type;
};

struct irdma_local_mac_entry_info {
	u8 mac_addr[6];
	u16 entry_idx;
};

struct irdma_add_arp_cache_entry_info {
	u8 mac_addr[ETH_ALEN];
	u32 reach_max;
	u16 arp_index;
	bool permanent;
};

struct irdma_apbvt_info {
	u16 port;
	bool add;
};

struct irdma_qhash_table_info {
	struct irdma_sc_vsi *vsi;
	enum irdma_quad_hash_manage_type manage;
	enum irdma_quad_entry_type entry_type;
	bool vlan_valid;
	bool ipv4_valid;
	u8 mac_addr[ETH_ALEN];
	u16 vlan_id;
	u8 user_pri;
	u32 qp_num;
	u32 dest_ip[4];
	u32 src_ip[4];
	u16 dest_port;
	u16 src_port;
};

struct irdma_cqp_manage_push_page_info {
	u32 push_idx;
	u16 qs_handle;
	u8 free_page;
	u8 push_page_type;
};

struct irdma_qp_flush_info {
	u16 sq_minor_code;
	u16 sq_major_code;
	u16 rq_minor_code;
	u16 rq_major_code;
	u16 ae_code;
	u8 ae_src;
	bool sq;
	bool rq;
	bool userflushcode;
	bool generate_ae;
};

struct irdma_gen_ae_info {
	u16 ae_code;
	u8 ae_src;
};

struct irdma_cqp_timeout {
	u64 compl_cqp_cmds;
	u32 count;
};

struct irdma_irq_ops {
	void (*irdma_cfg_aeq)(struct irdma_sc_dev *dev, u32 idx);
	void (*irdma_cfg_ceq)(struct irdma_sc_dev *dev, u32 ceq_id, u32 idx);
	void (*irdma_dis_irq)(struct irdma_sc_dev *dev, u32 idx);
	void (*irdma_en_irq)(struct irdma_sc_dev *dev, u32 idx);
};

struct irdma_cqp_ops {
	void (*check_cqp_progress)(struct irdma_cqp_timeout *cqp_timeout,
				   struct irdma_sc_dev *dev);
	enum irdma_status_code (*cqp_create)(struct irdma_sc_cqp *cqp,
					     u16 *maj_err, u16 *min_err);
	enum irdma_status_code (*cqp_destroy)(struct irdma_sc_cqp *cqp);
	__le64 *(*cqp_get_next_send_wqe)(struct irdma_sc_cqp *cqp, u64 scratch);
	enum irdma_status_code (*cqp_init)(struct irdma_sc_cqp *cqp,
					   struct irdma_cqp_init_info *info);
	void (*cqp_post_sq)(struct irdma_sc_cqp *cqp);
	enum irdma_status_code (*poll_for_cqp_op_done)(struct irdma_sc_cqp *cqp,
						       u8 opcode,
						       struct irdma_ccq_cqe_info *cmpl_info);
};

struct irdma_ccq_ops {
	void (*ccq_arm)(struct irdma_sc_cq *ccq);
	enum irdma_status_code (*ccq_create)(struct irdma_sc_cq *ccq,
					     u64 scratch, bool check_overflow,
					     bool post_sq);
	enum irdma_status_code (*ccq_create_done)(struct irdma_sc_cq *ccq);
	enum irdma_status_code (*ccq_destroy)(struct irdma_sc_cq *ccq, u64 scratch, bool post_sq);
	enum irdma_status_code (*ccq_get_cqe_info)(struct irdma_sc_cq *ccq,
						   struct irdma_ccq_cqe_info *info);
	enum irdma_status_code (*ccq_init)(struct irdma_sc_cq *ccq,
					   struct irdma_ccq_init_info *info);
};

struct irdma_ceq_ops {
	enum irdma_status_code (*ceq_create)(struct irdma_sc_ceq *ceq,
					     u64 scratch, bool post_sq);
	enum irdma_status_code (*cceq_create_done)(struct irdma_sc_ceq *ceq);
	enum irdma_status_code (*cceq_destroy_done)(struct irdma_sc_ceq *ceq);
	enum irdma_status_code (*cceq_create)(struct irdma_sc_ceq *ceq,
					      u64 scratch);
	enum irdma_status_code (*ceq_destroy)(struct irdma_sc_ceq *ceq,
					      u64 scratch, bool post_sq);
	enum irdma_status_code (*ceq_init)(struct irdma_sc_ceq *ceq,
					   struct irdma_ceq_init_info *info);
	void *(*process_ceq)(struct irdma_sc_dev *dev,
			     struct irdma_sc_ceq *ceq);
};

struct irdma_aeq_ops {
	enum irdma_status_code (*aeq_init)(struct irdma_sc_aeq *aeq,
					   struct irdma_aeq_init_info *info);
	enum irdma_status_code (*aeq_create)(struct irdma_sc_aeq *aeq,
					     u64 scratch, bool post_sq);
	enum irdma_status_code (*aeq_destroy)(struct irdma_sc_aeq *aeq,
					      u64 scratch, bool post_sq);
	enum irdma_status_code (*get_next_aeqe)(struct irdma_sc_aeq *aeq,
						struct irdma_aeqe_info *info);
	enum irdma_status_code (*repost_aeq_entries)(struct irdma_sc_dev *dev,
						     u32 count);
	enum irdma_status_code (*aeq_create_done)(struct irdma_sc_aeq *aeq);
	enum irdma_status_code (*aeq_destroy_done)(struct irdma_sc_aeq *aeq);
};

struct irdma_pd_ops {
	void (*pd_init)(struct irdma_sc_dev *dev, struct irdma_sc_pd *pd,
			u32 pd_id, int abi_ver);
};

struct irdma_priv_qp_ops {
	enum irdma_status_code (*iw_mr_fast_register)(struct irdma_sc_qp *qp,
						      struct irdma_fast_reg_stag_info *info,
						      bool post_sq);
	enum irdma_status_code (*qp_create)(struct irdma_sc_qp *qp,
					    struct irdma_create_qp_info *info,
					    u64 scratch, bool post_sq);
	enum irdma_status_code (*qp_destroy)(struct irdma_sc_qp *qp,
					     u64 scratch, bool remove_hash_idx,
					     bool ignore_mw_bnd, bool post_sq);
	enum irdma_status_code (*qp_flush_wqes)(struct irdma_sc_qp *qp,
						struct irdma_qp_flush_info *info,
						u64 scratch, bool post_sq);
	enum irdma_status_code (*qp_init)(struct irdma_sc_qp *qp,
					  struct irdma_qp_init_info *info);
	enum irdma_status_code (*qp_modify)(struct irdma_sc_qp *qp,
					    struct irdma_modify_qp_info *info,
					    u64 scratch, bool post_sq);
	void (*qp_send_lsmm)(struct irdma_sc_qp *qp, void *lsmm_buf, u32 size,
			     irdma_stag stag);
	void (*qp_send_lsmm_nostag)(struct irdma_sc_qp *qp, void *lsmm_buf,
				    u32 size);
	void (*qp_send_rtt)(struct irdma_sc_qp *qp, bool read);
	enum irdma_status_code (*qp_setctx)(struct irdma_sc_qp *qp,
					    __le64 *qp_ctx,
					    struct irdma_qp_host_ctx_info *info);
	enum irdma_status_code (*qp_setctx_roce)(struct irdma_sc_qp *qp, __le64 *qp_ctx,
						 struct irdma_qp_host_ctx_info *info);
	enum irdma_status_code (*qp_upload_context)(struct irdma_sc_dev *dev,
						    struct irdma_upload_context_info *info,
						    u64 scratch, bool post_sq);
	enum irdma_status_code (*update_suspend_qp)(struct irdma_sc_cqp *cqp,
						    struct irdma_sc_qp *qp,
						    u64 scratch);
	enum irdma_status_code (*update_resume_qp)(struct irdma_sc_cqp *cqp,
						   struct irdma_sc_qp *qp,
						   u64 scratch);
};

struct irdma_priv_cq_ops {
	void (*cq_ack)(struct irdma_sc_cq *cq);
	enum irdma_status_code (*cq_create)(struct irdma_sc_cq *cq, u64 scratch,
					    bool check_overflow, bool post_sq);
	enum irdma_status_code (*cq_destroy)(struct irdma_sc_cq *cq,
					     u64 scratch, bool post_sq);
	enum irdma_status_code (*cq_init)(struct irdma_sc_cq *cq,
					  struct irdma_cq_init_info *info);
	enum irdma_status_code (*cq_modify)(struct irdma_sc_cq *cq,
					    struct irdma_modify_cq_info *info,
					    u64 scratch, bool post_sq);
	void (*cq_resize)(struct irdma_sc_cq *cq, struct irdma_modify_cq_info *info);
};

struct irdma_mr_ops {
	enum irdma_status_code (*alloc_stag)(struct irdma_sc_dev *dev,
					     struct irdma_allocate_stag_info *info,
					     u64 scratch, bool post_sq);
	enum irdma_status_code (*dealloc_stag)(struct irdma_sc_dev *dev,
					       struct irdma_dealloc_stag_info *info,
					       u64 scratch, bool post_sq);
	enum irdma_status_code (*mr_reg_non_shared)(struct irdma_sc_dev *dev,
						    struct irdma_reg_ns_stag_info *info,
						    u64 scratch, bool post_sq);
	enum irdma_status_code (*mr_reg_shared)(struct irdma_sc_dev *dev,
						struct irdma_register_shared_stag *stag,
						u64 scratch, bool post_sq);
	enum irdma_status_code (*mw_alloc)(struct irdma_sc_dev *dev,
					   struct irdma_mw_alloc_info *info,
					   u64 scratch, bool post_sq);
	enum irdma_status_code (*query_stag)(struct irdma_sc_dev *dev, u64 scratch,
					     u32 stag_index, bool post_sq);
};

struct irdma_cqp_misc_ops {
	enum irdma_status_code (*add_arp_cache_entry)(struct irdma_sc_cqp *cqp,
						      struct irdma_add_arp_cache_entry_info *info,
						      u64 scratch, bool post_sq);
	enum irdma_status_code (*add_local_mac_entry)(struct irdma_sc_cqp *cqp,
						      struct irdma_local_mac_entry_info *info,
						      u64 scratch, bool post_sq);
	enum irdma_status_code (*alloc_local_mac_entry)(struct irdma_sc_cqp *cqp,
							u64 scratch,
							bool post_sq);
	enum irdma_status_code (*cqp_nop)(struct irdma_sc_cqp *cqp, u64 scratch, bool post_sq);
	enum irdma_status_code (*del_arp_cache_entry)(struct irdma_sc_cqp *cqp,
						      u64 scratch,
						      u16 arp_index,
						      bool post_sq);
	enum irdma_status_code (*del_local_mac_entry)(struct irdma_sc_cqp *cqp,
						      u64 scratch,
						      u16 entry_idx,
						      u8 ignore_ref_count,
						      bool post_sq);
	enum irdma_status_code (*gather_stats)(struct irdma_sc_cqp *cqp,
					       struct irdma_stats_gather_info *info,
					       u64 scratch);
	enum irdma_status_code (*manage_apbvt_entry)(struct irdma_sc_cqp *cqp,
						     struct irdma_apbvt_info *info,
						     u64 scratch, bool post_sq);
	enum irdma_status_code (*manage_push_page)(struct irdma_sc_cqp *cqp,
						   struct irdma_cqp_manage_push_page_info *info,
						   u64 scratch, bool post_sq);
	enum irdma_status_code (*manage_qhash_table_entry)(struct irdma_sc_cqp *cqp,
							   struct irdma_qhash_table_info *info,
							   u64 scratch, bool post_sq);
	enum irdma_status_code (*manage_stats_instance)(struct irdma_sc_cqp *cqp,
							struct irdma_stats_inst_info *info,
							bool alloc, u64 scratch);
	enum irdma_status_code (*manage_ws_node)(struct irdma_sc_cqp *cqp,
						 struct irdma_ws_node_info *info,
						 enum irdma_ws_node_op node_op,
						 u64 scratch);
	enum irdma_status_code (*query_arp_cache_entry)(struct irdma_sc_cqp *cqp,
							u64 scratch, u16 arp_index, bool post_sq);
	enum irdma_status_code (*query_rdma_features)(struct irdma_sc_cqp *cqp,
						      struct irdma_dma_mem *buf,
						      u64 scratch);
	enum irdma_status_code (*set_up_map)(struct irdma_sc_cqp *cqp,
					     struct irdma_up_info *info,
					     u64 scratch);
};

struct irdma_hmc_ops {
	enum irdma_status_code (*cfg_iw_fpm)(struct irdma_sc_dev *dev,
					     u8 hmc_fn_id);
	enum irdma_status_code (*commit_fpm_val)(struct irdma_sc_cqp *cqp,
						 u64 scratch, u8 hmc_fn_id,
						 struct irdma_dma_mem *commit_fpm_mem,
						 bool post_sq, u8 wait_type);
	enum irdma_status_code (*commit_fpm_val_done)(struct irdma_sc_cqp *cqp);
	enum irdma_status_code (*create_hmc_object)(struct irdma_sc_dev *dev,
						    struct irdma_hmc_create_obj_info *info);
	enum irdma_status_code (*del_hmc_object)(struct irdma_sc_dev *dev,
						 struct irdma_hmc_del_obj_info *info,
						 bool reset);
	enum irdma_status_code (*init_iw_hmc)(struct irdma_sc_dev *dev, u8 hmc_fn_id);
	enum irdma_status_code (*manage_hmc_pm_func_table)(struct irdma_sc_cqp *cqp,
							   u64 scratch,
							   u8 vf_index,
							   bool free_pm_fcn,
							   bool post_sq);
	enum irdma_status_code (*manage_hmc_pm_func_table_done)(struct irdma_sc_cqp *cqp);
	enum irdma_status_code (*parse_fpm_commit_buf)(struct irdma_sc_dev *dev,
						       __le64 *buf,
						       struct irdma_hmc_obj_info *info,
						       u32 *sd);
	enum irdma_status_code (*parse_fpm_query_buf)(struct irdma_sc_dev *dev,
						      __le64 *buf,
						      struct irdma_hmc_info *hmc_info,
						      struct irdma_hmc_fpm_misc *hmc_fpm_misc);
	enum irdma_status_code (*pf_init_vfhmc)(struct irdma_sc_dev *dev,
						u8 vf_hmc_fn_id,
						u32 *vf_cnt_array);
	enum irdma_status_code (*query_fpm_val)(struct irdma_sc_cqp *cqp,
						u64 scratch,
						u8 hmc_fn_id,
						struct irdma_dma_mem *query_fpm_mem,
						bool post_sq, u8 wait_type);
	enum irdma_status_code (*query_fpm_val_done)(struct irdma_sc_cqp *cqp);
	enum irdma_status_code (*static_hmc_pages_allocated)(struct irdma_sc_cqp *cqp,
							     u64 scratch,
							     u8 hmc_fn_id,
							     bool post_sq,
							     bool poll_registers);
	enum irdma_status_code (*vf_cfg_vffpm)(struct irdma_sc_dev *dev, u32 *vf_cnt_array);
};

struct cqp_info {
	union {
		struct {
			struct irdma_sc_qp *qp;
			struct irdma_create_qp_info info;
			u64 scratch;
		} qp_create;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_modify_qp_info info;
			u64 scratch;
		} qp_modify;

		struct {
			struct irdma_sc_qp *qp;
			u64 scratch;
			bool remove_hash_idx;
			bool ignore_mw_bnd;
		} qp_destroy;

		struct {
			struct irdma_sc_cq *cq;
			u64 scratch;
			bool check_overflow;
		} cq_create;

		struct {
			struct irdma_sc_cq *cq;
			struct irdma_modify_cq_info info;
			u64 scratch;
		} cq_modify;

		struct {
			struct irdma_sc_cq *cq;
			u64 scratch;
		} cq_destroy;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_allocate_stag_info info;
			u64 scratch;
		} alloc_stag;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_mw_alloc_info info;
			u64 scratch;
		} mw_alloc;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_reg_ns_stag_info info;
			u64 scratch;
		} mr_reg_non_shared;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_dealloc_stag_info info;
			u64 scratch;
		} dealloc_stag;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_add_arp_cache_entry_info info;
			u64 scratch;
		} add_arp_cache_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
			u16 arp_index;
		} del_arp_cache_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_local_mac_entry_info info;
			u64 scratch;
		} add_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
			u8 entry_idx;
			u8 ignore_ref_count;
		} del_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
		} alloc_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_cqp_manage_push_page_info info;
			u64 scratch;
		} manage_push_page;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_upload_context_info info;
			u64 scratch;
		} qp_upload_context;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_hmc_fcn_info info;
			u64 scratch;
		} manage_hmc_pm;

		struct {
			struct irdma_sc_ceq *ceq;
			u64 scratch;
		} ceq_create;

		struct {
			struct irdma_sc_ceq *ceq;
			u64 scratch;
		} ceq_destroy;

		struct {
			struct irdma_sc_aeq *aeq;
			u64 scratch;
		} aeq_create;

		struct {
			struct irdma_sc_aeq *aeq;
			u64 scratch;
		} aeq_destroy;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_qp_flush_info info;
			u64 scratch;
		} qp_flush_wqes;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_gen_ae_info info;
			u64 scratch;
		} gen_ae;

		struct {
			struct irdma_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u8 hmc_fn_id;
			u64 scratch;
		} query_fpm_val;

		struct {
			struct irdma_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u8 hmc_fn_id;
			u64 scratch;
		} commit_fpm_val;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_apbvt_info info;
			u64 scratch;
		} manage_apbvt_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_qhash_table_info info;
			u64 scratch;
		} manage_qhash_table_entry;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_update_sds_info info;
			u64 scratch;
		} update_pe_sds;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_sc_qp *qp;
			u64 scratch;
		} suspend_resume;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ah_info info;
			u64 scratch;
		} ah_create;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ah_info info;
			u64 scratch;
		} ah_destroy;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_create;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_destroy;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_modify;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_stats_inst_info info;
			u64 scratch;
		} stats_manage;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_stats_gather_info info;
			u64 scratch;
		} stats_gather;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ws_node_info info;
			u64 scratch;
		} ws_node;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_up_info info;
			u64 scratch;
		} up_map;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_dma_mem query_buff_mem;
			u64 scratch;
		} query_rdma;
	} u;
};

struct cqp_cmds_info {
	struct list_head cqp_cmd_entry;
	u8 cqp_cmd;
	u8 post_sq;
	struct cqp_info in;
};

struct irdma_virtchnl_work_info {
	void (*callback_fcn)(void *vf_dev);
	void *worker_vf_dev;
};
#endif /* IRDMA_TYPE_H */
