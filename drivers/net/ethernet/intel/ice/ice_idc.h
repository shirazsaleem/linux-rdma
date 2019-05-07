/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018, Intel Corporation. */

#ifndef _ICE_IDC_H_
#define _ICE_IDC_H_

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/dcbnl.h>

/* This major and minor version represent IDC API version information.
 * During peer driver registration, peer driver specifies major and minor
 * version information (via. peer_driver:ver_info). It gets checked against
 * following defines and if mismatch, then peer driver registration
 * fails and appropriate message gets logged.
 */
#define ICE_PEER_MAJOR_VER		5
#define ICE_PEER_MINOR_VER		2

enum ice_event_type {
	ICE_EVENT_LINK_CHANGE = 0x0,
	ICE_EVENT_MTU_CHANGE,
	ICE_EVENT_TC_CHANGE,
	ICE_EVENT_API_CHANGE,
	ICE_EVENT_MBX_CHANGE,
	ICE_EVENT_NBITS		/* must be last */
};

enum ice_res_type {
	ICE_INVAL_RES = 0x0,
	ICE_VSI,
	ICE_VEB,
	ICE_EVENT_Q,
	ICE_EGRESS_CMPL_Q,
	ICE_CMPL_EVENT_Q,
	ICE_ASYNC_EVENT_Q,
	ICE_DOORBELL_Q,
	ICE_RDMA_QSETS_TXSCHED,
};

enum ice_peer_reset_type {
	ICE_PEER_PFR = 0,
	ICE_PEER_CORER,
	ICE_PEER_CORER_SW_CORE,
	ICE_PEER_CORER_SW_FULL,
	ICE_PEER_GLOBR,
};

/* reason notified to peer driver as part of event handling */
enum ice_close_reason {
	ICE_REASON_INVAL = 0x0,
	ICE_REASON_HW_UNRESPONSIVE,
	ICE_REASON_INTERFACE_DOWN, /* Administrative down */
	ICE_REASON_PEER_DRV_UNREG, /* peer driver getting unregistered */
	ICE_REASON_PEER_DEV_UNINIT,
	ICE_REASON_GLOBR_REQ,
	ICE_REASON_CORER_REQ,
	ICE_REASON_EMPR_REQ,
	ICE_REASON_PFR_REQ,
	ICE_REASON_HW_RESET_PENDING,
	ICE_REASON_PARAM_CHANGE,
};

enum ice_rdma_filter {
	ICE_RDMA_FILTER_INVAL = 0x0,
	ICE_RDMA_FILTER_IWARP,
	ICE_RDMA_FILTER_ROCEV2,
	ICE_RDMA_FILTER_BOTH,
};

/* This information is needed to handle peer driver registration,
 * instead of adding more params to peer_drv_registration function,
 * let's get it thru' peer_drv object.
 */
struct ice_ver_info {
	u16 major;
	u16 minor;
	u16 support;
};

/* Struct to hold per DCB APP info */
struct ice_dcb_app_info {
	u8  priority;
	u8  selector;
	u16 prot_id;
};

struct ice_peer_dev;

#define ICE_IDC_MAX_USER_PRIORITY        8
#define ICE_IDC_MAX_APPS        8

/* Struct to hold per RDMA Qset info */
struct ice_rdma_qset_params {
	u32 teid;	/* qset TEID */
	u16 qs_handle; /* RDMA driver provides this */
	u16 vsi_id; /* VSI index */
	u8 tc; /* TC branch the QSet should belong to */
	u8 reserved[3];
};

struct ice_res_base {
	/* Union for future provision e.g. other res_type */
	union {
		struct ice_rdma_qset_params qsets;
	} res;
};

struct ice_res {
	/* Type of resource. Filled by peer driver */
	enum ice_res_type res_type;
	/* Count requested by peer driver */
	u16 cnt_req;

	/* Number of resources allocated. Filled in by callee.
	 * Based on this value, caller to fill up "resources"
	 */
	u16 res_allocated;

	/* Unique handle to resources allocated. Zero if call fails.
	 * Allocated by callee and for now used by caller for internal
	 * tracking purpose.
	 */
	u32 res_handle;

	/* Peer driver has to allocate sufficient memory, to accommodate
	 * cnt_requested before calling this function.
	 * Memory has to be zero initialized. It is input/output param.
	 * As a result of alloc_res API, this structures will be populated.
	 */
	struct ice_res_base res[1];
};

struct ice_vector_info {
	u32 v_idx; /* MSIx vector */
	u16 itr_idx;
	/* This is the register address of GLINT_DYN_CTL[idx], not value */
	u64 itr_dyn_ctl_reg;
	/* This is the register address of GLINT_RATE[idx], not value */
	u64 itr_rate_lmt_reg;
};

struct ice_vector_list {
	u32 num_vectors;
	struct ice_vector_info *vector;
	/* Unique handle to resources allocated.
	 * Zero if call fails
	 */
	u32 res_handle;
};

struct ice_itr_regs {
	u16 cnt;
	u64 *tmr_regs;
	u32 res_handle;
};

struct ice_qos_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

/* Struct to hold QoS info */
struct ice_qos_params {
	struct ice_qos_info tc_info[IEEE_8021QAZ_MAX_TCS];
	u8 up2tc[ICE_IDC_MAX_USER_PRIORITY];
	u8 vsi_relative_bw;
	u8 vsi_priority_type;
	u32 num_apps;
	struct ice_dcb_app_info apps[ICE_IDC_MAX_APPS];
	u8 num_tc;
};

union ice_event_info {
	/* ICE_EVENT_LINK_CHANGE */
	struct {
		struct net_device *lwr_nd;
		u16 vsi_num; /* HW index of VSI corresponding to lwr ndev */
		u8 new_link_state;
		u8 lport;
	} link_info;
	/* ICE_EVENT_MTU_CHANGE */
	u16 mtu;
	/* ICE_EVENT_TC_CHANGE */
	struct ice_qos_params port_qos;
	/* ICE_EVENT_API_CHANGE */
	u8 api_rdy;
	/* ICE_EVENT_MBX_CHANGE */
	u8 mbx_rdy;
};

/* ice_event elements are to be passed back and forth between the ice driver
 * and the peer drivers. They are to be used to both register/unregister
 * for event reporting and to report an event (events can be either ice
 * generated or peer generated).
 *
 * For (un)registering for events, the structure needs to be populated with:
 *   reporter - pointer to the ice_peer_dev struct of the peer (un)registering
 *   type - bitmap with bits set for event types to (un)register for
 *
 * For reporting events, the structure needs to be populated with:
 *   reporter - pointer to peer that generated the event (NULL for ice)
 *   type - bitmap with single bit set for this event type
 *   info - union containing data relevant to this event type
 */
struct ice_event {
	struct ice_peer_dev *reporter;
	DECLARE_BITMAP(type, ICE_EVENT_NBITS);
	union ice_event_info info;
};

/* Following APIs are implemented by ICE driver and invoked by peer drivers */
struct ice_ops {
	/* APIs to allocate resources such as VEB, VSI, Doorbell queues,
	 * completion queues, Tx/Rx queues, etc...
	 */
	int (*alloc_res)(struct ice_peer_dev *peer_dev,
			 struct ice_res *res,
			 int partial_acceptable);
	int (*free_res)(struct ice_peer_dev *peer_dev,
			struct ice_res *res);

	/* Interrupt/Vector related APIs */
	int (*alloc_msix_vector)(struct ice_peer_dev *peer_dev,
				 int count, struct ice_vector_list *entries);
	int (*free_msix_vector)(struct ice_peer_dev *peer_dev,
				int count, struct ice_vector_list *entries);
	int (*associate_vector_cause)(struct ice_peer_dev *peer_dev,
				      struct ice_vector_info *qv_info,
				      enum ice_res_type res_type,
				      int res_idx);
	int (*request_uninit)(struct ice_peer_dev *peer_dev);
	int (*request_reinit)(struct ice_peer_dev *peer_dev);
	int (*request_reset)(struct ice_peer_dev *dev,
			     enum ice_peer_reset_type reset_type);

	void (*notify_state_change)(struct ice_peer_dev *dev,
				    struct ice_event *event);

	/* Notification APIs */
	void (*reg_for_notification)(struct ice_peer_dev *dev,
				     struct ice_event *event);
	void (*unreg_for_notification)(struct ice_peer_dev *dev,
				       struct ice_event *event);
	int (*update_vsi_filter)(struct ice_peer_dev *peer_dev,
				 enum ice_rdma_filter filter, bool enable);
	int (*vc_send)(struct ice_peer_dev *peer_dev, u32 vf_id, u8 *msg,
		       u16 len);
};

/* Following APIs are implemented by peer drivers and invoked by ICE driver */
struct ice_peer_ops {
	void (*event_handler)(struct ice_peer_dev *peer_dev,
			      struct ice_event *event);

	/* Why we have 'open' and when it is expected to be called:
	 * 1. symmetric set of API w.r.t close
	 * 2. To be invoked form driver initialization path
	 *     - call peer_driver:probe as soon as ice driver:probe is done
	 *     - call peer_driver:open once ice driver is fully initialized
	 * 3. To be invoked upon RESET complete
	 *
	 * Calls to open are performed from ice_finish_init_peer_device
	 * which is invoked from the service task. This helps keep devices
	 * from having their open called until the ice driver is ready and
	 * has scheduled its service task.
	 */
	void (*open)(struct ice_peer_dev *peer_dev);

	/* Peer's close function is to be called when the peer needs to be
	 * quiesced. This can be for a variety of reasons (enumerated in the
	 * ice_close_reason enum struct). A call to close will only be
	 * followed by a call to either remove or open. No IDC calls from the
	 * peer should be accepted until it is re-opened.
	 *
	 * The *reason* parameter is the reason for the call to close. This
	 * can be for any reason enumerated in the ice_close_reason struct.
	 * It's primary reason is for the peer's bookkeeping and in case the
	 * peer want to perform any different tasks dictated by the reason.
	 */
	void (*close)(struct ice_peer_dev *peer_dev,
		      enum ice_close_reason reason);

	int (*vc_receive)(struct ice_peer_dev *peer_dev, u32 vf_id, u8 *msg,
			  u16 len);
	/* tell RDMA peer to prepare for TC change in a blocking call
	 * that will directly precede the change event
	 */
	void (*prep_tc_change)(struct ice_peer_dev *peer_dev);
};

struct ice_peer_device_id {
	u32 vendor;

	u32 device;
#define ICE_PEER_RDMA_DEV	0x00000010
};

/* structure representing peer device */
struct ice_peer_dev {
	struct device dev;
	struct pci_dev *pdev; /* PCI device of corresponding to main function */
	struct ice_peer_device_id dev_id;
	/* KVA / Linear address corresponding to BAR0 of underlying
	 * pci_device.
	 */
	u8 __iomem *hw_addr;

	unsigned int index;

	u8 ftype;	/* PF(false) or VF (true) */

	/* Data VSI created by driver */
	u16 pf_vsi_num;

	u8 lan_addr[ETH_ALEN]; /* default MAC address of main netdev */
	u16 initial_mtu; /* Initial MTU of main netdev */
	struct ice_qos_params initial_qos_info;
	struct net_device *netdev;
	/* PCI info */
	u8 ari_ena;
	u16 bus_num;
	u16 dev_num;
	u16 fn_num;

	/* Based on peer driver type, this shall point to corresponding MSIx
	 * entries in pf->msix_entries (which were allocated as part of driver
	 * initialization) e.g. for RDMA driver, msix_entries reserved will be
	 * num_online_cpus + 1.
	 */
	u16 msix_count; /* How many vectors are reserved for this device */
	struct msix_entry *msix_entries;

	/* Following struct contains function pointers to be initialized
	 * by ICE driver and called by peer driver
	 */
	const struct ice_ops *ops;

	/* Following struct contains function pointers to be initialized
	 * by peer driver and called by ICE driver
	 */
	const struct ice_peer_ops *peer_ops;
};

static inline struct ice_peer_dev *dev_to_ice_peer(struct device *_dev)
{
	return container_of(_dev, struct ice_peer_dev, dev);
}

/* structure representing peer driver
 * Peer driver to initialize those function ptrs and
 * it will be invoked by ICE as part of driver_registration
 * via bus infrastructure
 */
struct ice_peer_drv {
	u16 driver_id;
#define ICE_PEER_LAN_DRIVER		0
#define ICE_PEER_RDMA_DRIVER		4
#define ICE_PEER_ADK_DRIVER		5

	struct ice_ver_info ver;
	const char *name;

	struct device_driver driver;
	struct ice_peer_device_id dev_id;

	/* As part of ice_peer_drv initialization, peer driver is expected
	 * to initialize driver.probe and driver.remove callbacks to peer
	 * driver's respective probe and remove.
	 *
	 * driver_registration invokes driver->probe and likewise
	 * driver_unregistration invokes driver->remove
	 */
	int (*probe)(struct ice_peer_dev *dev);
	int (*remove)(struct ice_peer_dev *dev);
};

#define IDC_SIGNATURE 0x494e54454c494443ULL
struct idc_srv_provider {
	u64 signature;
	u16 maj_ver;
	u16 min_ver;
	u8 rsvd[4];
	int (*reg_peer_driver)(struct ice_peer_drv *drv);
	int (*unreg_peer_driver)(struct ice_peer_drv *drv);
};

static inline struct ice_peer_drv *drv_to_ice_peer(struct device_driver *drv)
{
	return container_of(drv, struct ice_peer_drv, driver);
};

/* Exported symbols for driver registration/unregistration */
int ice_reg_peer_driver(struct ice_peer_drv *peer);
int ice_unreg_peer_driver(struct ice_peer_drv *peer);
#endif /* _ICE_IDC_H_*/
