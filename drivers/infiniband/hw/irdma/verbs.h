/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2019, Intel Corporation. */

#ifndef IRDMA_VERBS_H
#define IRDMA_VERBS_H

#define IRDMA_MAX_SAVED_PHY_PGADDR	4

#define IRDMA_PKEY_TBL_SZ		1
#define IRDMA_DEFAULT_PKEY		0xFFFF

struct irdma_ucontext {
	struct ib_ucontext ibucontext;
	struct irdma_device *iwdev;
	struct list_head cq_reg_mem_list;
	spinlock_t cq_reg_mem_list_lock; /* protect CQ memory list */
	struct list_head qp_reg_mem_list;
	spinlock_t qp_reg_mem_list_lock; /* protect QP memory list */
	int abi_ver;
};

struct irdma_pd {
	struct ib_pd ibpd;
	struct irdma_sc_pd sc_pd;
/* TODO: remove */
};

struct irdma_av {
	u8 macaddr[16];
	struct rdma_ah_attr attrs;
	union {
		struct sockaddr saddr;
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sgid_addr, dgid_addr;
	u8 net_type;
};

struct irdma_ah {
	struct ib_ah ibah;
	struct irdma_sc_ah sc_ah;
	atomic_t usecount;
	struct irdma_pd *pd;
	struct irdma_av av;
	u8 sgid_index;
	union ib_gid dgid;
};

struct irdma_hmc_pble {
	union {
		u32 idx;
		dma_addr_t addr;
	};
};

struct irdma_cq_mr {
	struct irdma_hmc_pble cq_pbl;
	dma_addr_t shadow;
	bool split;
};

struct irdma_qp_mr {
	struct irdma_hmc_pble sq_pbl;
	struct irdma_hmc_pble rq_pbl;
	dma_addr_t shadow;
	struct page *sq_page;
};

struct irdma_cq_buf {
	struct irdma_dma_mem kmem_buf;
	struct irdma_cq_uk cq_uk;
	struct irdma_hw *hw;
	struct list_head list;
	struct work_struct work;
};

struct irdma_pbl {
	struct list_head list;
	union {
		struct irdma_qp_mr qp_mr;
		struct irdma_cq_mr cq_mr;
	};

	bool pbl_allocated;
	bool on_list;
	u64 user_base;
	struct irdma_pble_alloc pble_alloc;
	struct irdma_mr *iwmr;
};

struct irdma_mr {
	union {
		struct ib_mr ibmr;
		struct ib_mw ibmw;
		struct ib_fmr ibfmr;
	};
	struct ib_umem *region;
	u16 type;
	u32 page_cnt;
	u32 page_size;
	u64 page_msk;
	u32 npages;
	u32 stag;
	u64 len;
	u64 pgaddrmem[IRDMA_MAX_SAVED_PHY_PGADDR];
	struct irdma_pbl iwpbl;
};

struct irdma_cq {
	struct ib_cq ibcq;
	struct irdma_sc_cq sc_cq;
	u16 cq_head;
	u16 cq_size;
	u16 cq_num;
	bool user_mode;
	u32 polled_cmpls;
	u32 cq_mem_size;
	struct irdma_dma_mem kmem;
	struct irdma_dma_mem kmem_shadow;
	spinlock_t lock; /* for poll cq */
	struct irdma_pbl *iwpbl;
	struct irdma_pbl *iwpbl_shadow;
	struct list_head resize_list;
};

struct disconn_work {
	struct work_struct work;
	struct irdma_qp *iwqp;
};

struct iw_cm_id;

struct irdma_qp_kmode {
	struct irdma_dma_mem dma_mem;
	u64 *wrid_mem;
};

struct irdma_qp {
	struct ib_qp ibqp;
	struct irdma_sc_qp sc_qp;
	struct irdma_device *iwdev;
	struct irdma_cq *iwscq;
	struct irdma_cq *iwrcq;
	struct irdma_pd *iwpd;
	struct irdma_qp_host_ctx_info ctx_info;
	union {
		struct irdma_iwarp_offload_info iwarp_info;
		struct irdma_roce_offload_info roce_info;
	};

	union {
		struct irdma_tcp_offload_info tcp_info;
		struct irdma_udp_offload_info udp_info;
	};

	struct irdma_ah roce_ah;
	struct list_head teardown_entry;
	atomic_t refcount;
	struct iw_cm_id *cm_id;
	void *cm_node;
	struct ib_mr *lsmm_mr;
	struct work_struct work;
	atomic_t hw_mod_qp_pend;
	enum ib_qp_state ibqp_state;
	u32 qp_mem_size;
	u32 last_aeq;
	int max_send_wr;
	int max_recv_wr;
	atomic_t close_timer_started;
	spinlock_t lock; /* serialize posting WRs to SQ/RQ */
	struct irdma_qp_context *iwqp_context;
	void *pbl_vbase;
	dma_addr_t pbl_pbase;
	struct page *page;
	u8 active_conn : 1;
	u8 user_mode : 1;
	u8 hte_added : 1;
	u8 flush_issued : 1;
	u8 destroyed : 1;
	u8 sig_all : 1;
	u8 pau_mode : 1;
	u8 rsvd : 1;
	u8 iwarp_state;
	u16 term_sq_flush_code;
	u16 term_rq_flush_code;
	u8 hw_iwarp_state;
	u8 hw_tcp_state;
	struct irdma_qp_kmode kqp;
	struct irdma_dma_mem host_ctx;
	struct timer_list terminate_timer;
	struct irdma_pbl *iwpbl;
	struct irdma_dma_mem q2_ctx_mem;
	struct irdma_dma_mem ietf_mem;
	struct completion sq_drained;
	struct completion rq_drained;
	atomic_t mcast_ref_cnt;
	wait_queue_head_t waitq;
	wait_queue_head_t mod_qp_waitq;
	u8 rts_ae_rcvd;
};

void irdma_mcast_mac(u32 *ip_addr, u8 *mac, bool ipv4);
#endif /* IRDMA_VERBS_H */
