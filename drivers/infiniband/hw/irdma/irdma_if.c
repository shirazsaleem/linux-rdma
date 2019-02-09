// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2019, Intel Corporation. */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <ice_idc.h>
#include "main.h"
#include "ws.h"
#include "icrdma_hw.h"

/**
 * irdma_lan_register_qset - Register qset with LAN driver
 * @vsi: vsi structure
 * @tc_node: Traffic class node
 */
enum irdma_status_code irdma_lan_register_qset(struct irdma_sc_vsi *vsi,
					       struct irdma_ws_node *tc_node)
{
	struct irdma_device *iwdev = vsi->back_vsi;
	struct ice_peer_dev *ldev = (struct ice_peer_dev *)iwdev->ldev->if_ldev;
	struct ice_res rdma_qset_res = {};
	int ret;

	if (ldev->ops->alloc_res) {
		rdma_qset_res.cnt_req = 1;
		rdma_qset_res.res_type = ICE_RDMA_QSETS_TXSCHED;
		rdma_qset_res.res[0].res.qsets.qs_handle = tc_node->qs_handle;
		rdma_qset_res.res[0].res.qsets.tc = tc_node->traffic_class;
		rdma_qset_res.res[0].res.qsets.vsi_id = vsi->vsi_idx;
		ret = ldev->ops->alloc_res(ldev, &rdma_qset_res, 0);
		if (ret) {
			irdma_debug(vsi->dev, IRDMA_DEBUG_WS,
				    "LAN alloc_res for rdma qset failed.\n");
			return IRDMA_ERR_NO_MEMORY;
		}

		tc_node->l2_sched_node_id = rdma_qset_res.res[0].res.qsets.teid;
		vsi->qos[tc_node->user_pri].l2_sched_node_id =
			rdma_qset_res.res[0].res.qsets.teid;
	}

	return 0;
}

/**
 * irdma_lan_unregister_qset - Unregister qset with LAN driver
 * @vsi: vsi structure
 * @tc_node: Traffic class node
 */
void irdma_lan_unregister_qset(struct irdma_sc_vsi *vsi,
			       struct irdma_ws_node *tc_node)
{
	struct irdma_device *iwdev = vsi->back_vsi;
	struct ice_peer_dev *ldev = (struct ice_peer_dev *)iwdev->ldev->if_ldev;
	struct ice_res rdma_qset_res = {};

	if (ldev->ops->free_res) {
		rdma_qset_res.res_allocated = 1;
		rdma_qset_res.res_type = ICE_RDMA_QSETS_TXSCHED;
		rdma_qset_res.res[0].res.qsets.vsi_id = vsi->vsi_idx;
		rdma_qset_res.res[0].res.qsets.teid = tc_node->l2_sched_node_id;
		rdma_qset_res.res[0].res.qsets.qs_handle = tc_node->qs_handle;

		if (ldev->ops->free_res(ldev, &rdma_qset_res))
			irdma_debug(vsi->dev, IRDMA_DEBUG_WS,
				    "LAN free_res for rdma qset failed.\n");
	}
}

/**
 * irdma_log_invalid_mtu: log warning on invalid mtu
 * @mtu: maximum tranmission unit
 */
static void irdma_log_invalid_mtu(u16 mtu)
{
	if (mtu < IRDMA_MIN_MTU_IPV4)
		pr_warn("Current MTU setting of %d is too low for RDMA traffic. Minimum MTU is 576 for IPv4 and 1280 for IPv6\n",
		        mtu);
	else if (mtu < IRDMA_MIN_MTU_IPV6)
		pr_warn("Current MTU setting of %d is too low for IPv6 RDMA traffic, the minimum is 1280\n",
		        mtu);
}

/**
 * irdma_prep_tc_change - Prepare for TC changes
 * @ldev: Peer device structure
 */
static void irdma_prep_tc_change(struct ice_peer_dev *ldev)
{
	struct irdma_device *iwdev;

	iwdev = irdma_get_device(ldev->netdev);
	if (!iwdev)
		return;

	if (iwdev->vsi.tc_change_pending)
		goto done;

	iwdev->vsi.tc_change_pending = true;
	irdma_suspend_qps(&iwdev->vsi);

	/* Wait for all qp's to suspend */
	wait_event_timeout(iwdev->suspend_wq,
			   !atomic_read(&iwdev->vsi.qp_suspend_reqs),
			   IRDMA_EVENT_TIMEOUT);
	irdma_ws_reset(&iwdev->vsi);
done:
	irdma_put_device(iwdev);
}

/**
 * irdma_event_handler - Called by LAN driver to notify events
 * @ldev: Peer device structure
 * @event: event from LAN driver
 */
static void irdma_event_handler(struct ice_peer_dev *ldev,
				struct ice_event *event)
{
	struct irdma_l2params l2params = {};
	struct irdma_device *iwdev;
	u8 first_tc;
	int i;

	iwdev = irdma_get_device(ldev->netdev);
	if (!iwdev)
		return;

	if (test_bit(ICE_EVENT_LINK_CHANGE, event->type)) {
		irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_CLNT,
			    "LINK_CHANGE event\n");
	} else if (test_bit(ICE_EVENT_MTU_CHANGE, event->type)) {
		irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_CLNT,
			    "new MTU = %d\n", event->info.mtu);
		if (iwdev->vsi.mtu != event->info.mtu) {
			l2params.mtu = event->info.mtu;
			l2params.mtu_changed = true;
			irdma_log_invalid_mtu(l2params.mtu);
			irdma_change_l2params(&iwdev->vsi, &l2params);
		}
	} else if (test_bit(ICE_EVENT_TC_CHANGE, event->type)) {
		if (!iwdev->vsi.tc_change_pending)
			goto done;

		l2params.tc_changed = true;
		irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_CLNT,
			    "TC Change\n");
		first_tc = event->info.port_qos.up2tc[0];
		iwdev->dcb = false;
		for (i = 0; i < ICE_IDC_MAX_USER_PRIORITY; ++i) {
			l2params.up2tc[i] = event->info.port_qos.up2tc[i];
			if (first_tc != l2params.up2tc[i])
				iwdev->dcb = true;
		}
		irdma_change_l2params(&iwdev->vsi, &l2params);
	} else if (test_bit(ICE_EVENT_API_CHANGE, event->type)) {
		irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_CLNT,
			    "API_CHANGE\n");
	}

done:
	irdma_put_device(iwdev);

	return;
}

/**
 * irdma_open - client interface operation open for RDMA device
 * @ldev: lan device information
 *
 * Called by the lan driver during the processing of client
 * register.
 */
static void irdma_open(struct ice_peer_dev *ldev)
{
	struct irdma_handler *hdl;
	struct irdma_device *iwdev;
	struct irdma_sc_dev *dev;
	enum irdma_status_code status;
	struct ice_event events = {};
	struct irdma_pci_f *rf;
	struct irdma_priv_ldev *pldev;
	struct irdma_l2params l2params = {};
	int i;

	hdl = irdma_find_handler(ldev->pdev);
	if (!hdl)
		return;

	rf = &hdl->rf;
	if (rf->init_state != CEQ0_CREATED)
		return;

	iwdev = kzalloc(sizeof(*iwdev), GFP_KERNEL);
	if (!iwdev)
		return;

	iwdev->hdl = hdl;
	iwdev->rf = rf;
	iwdev->ldev = &rf->ldev;
	pldev = &rf->ldev;
	pldev->pf_vsi_num = ldev->pf_vsi_num;

	/* Set configfs default values */
	iwdev->push_mode = 0;
	iwdev->rcv_wnd = IRDMA_CM_DEFAULT_RCV_WND_SCALED;
	iwdev->rcv_wscale = IRDMA_CM_DEFAULT_RCV_WND_SCALE;

	dev = &hdl->rf.sc_dev;
	iwdev->netdev = ldev->netdev;
	iwdev->create_ilq = true;
	if (rf->roce_ena & (1 << ldev->index)) { /* A bit per port */
		iwdev->roce_mode = true;
		iwdev->create_ilq = false;
	}
	l2params.mtu = ldev->initial_mtu;

	l2params.num_tc = ldev->initial_qos_info.num_tc;
	l2params.num_apps = ldev->initial_qos_info.num_apps;
	l2params.vsi_prio_type = ldev->initial_qos_info.vsi_priority_type;
	l2params.vsi_rel_bw = ldev->initial_qos_info.vsi_relative_bw;
	for (i = 0; i < l2params.num_tc; i++) {
		l2params.tc_info[i].egress_virt_up =
			ldev->initial_qos_info.tc_info[i].egress_virt_up;
		l2params.tc_info[i].ingress_virt_up =
			ldev->initial_qos_info.tc_info[i].ingress_virt_up;
		l2params.tc_info[i].prio_type =
			ldev->initial_qos_info.tc_info[i].prio_type;
		l2params.tc_info[i].rel_bw =
			ldev->initial_qos_info.tc_info[i].rel_bw;
		l2params.tc_info[i].tc_ctx =
			ldev->initial_qos_info.tc_info[i].tc_ctx;
	}
	for (i = 0; i < ICE_IDC_MAX_USER_PRIORITY; i++)
		l2params.up2tc[i] = ldev->initial_qos_info.up2tc[i];

	iwdev->vsi_num = ldev->pf_vsi_num;
	ldev->ops->update_vsi_filter(ldev, ICE_RDMA_FILTER_BOTH, true);

	status = irdma_rt_init_hw(rf, iwdev, &l2params);
	if (status) {
		kfree(iwdev);
		return;
	}

	events.reporter = ldev;
	set_bit(ICE_EVENT_LINK_CHANGE, events.type);
	set_bit(ICE_EVENT_MTU_CHANGE, events.type);
	set_bit(ICE_EVENT_TC_CHANGE, events.type);
	set_bit(ICE_EVENT_API_CHANGE, events.type);

	if (ldev->ops->reg_for_notification)
		ldev->ops->reg_for_notification(ldev, &events);
	dev_info(to_device(dev), "IRDMA VSI Open Successful");
	init_waitqueue_head(&iwdev->suspend_wq);
}

/**
 * irdma_close - client interface operation close for iwarp/uda device
 * @ldev: lan device information
 * @reason: reason for closing
 *
 * Called by the lan driver during the processing of client unregister
 * Destroy and clean up the driver resources
 */
static void irdma_close(struct ice_peer_dev *ldev, enum ice_close_reason reason)
{
	struct irdma_device *iwdev;

	iwdev = irdma_get_device(ldev->netdev);
	if (!iwdev)
		return;

	irdma_put_device(iwdev);
	if (reason == ICE_REASON_HW_RESET_PENDING) {
		iwdev->reset = true;
		iwdev->rf->reset = true;
	}

	if (iwdev->init_state >= CEQ0_CREATED)
		irdma_deinit_rt_device(iwdev);

	kfree(iwdev);
	ldev->ops->update_vsi_filter(ldev, ICE_RDMA_FILTER_BOTH, false);
	pr_info("IRDMA VSI close complete\n");
}

/**
 * irdma_remove - client interface remove operation for RDMA
 * @ldev: lan device information
 *
 * Called on module unload.
 */
static int irdma_remove(struct ice_peer_dev *ldev)
{
	struct irdma_handler *hdl;
	struct irdma_pci_f *rf;

	hdl = irdma_find_handler(ldev->pdev);
	if (!hdl)
		return 0;

	rf = &hdl->rf;
	if (rf->init_state != CEQ0_CREATED)
		return -EBUSY;

	if (rf->free_qp_wq)
		destroy_workqueue(rf->free_qp_wq);
	if (rf->free_cqbuf_wq)
		destroy_workqueue(rf->free_cqbuf_wq);
	irdma_deinit_ctrl_hw(rf);
	irdma_del_handler(hdl);
	kfree(hdl);
	irdma_probe_dec_ref(ldev->netdev);
	pr_info("IRDMA hardware deinitialization complete\n");

	return 0;
}

static const struct ice_peer_ops irdma_peer_ops = {
	.close = irdma_close,
	.event_handler = irdma_event_handler,
	.open = irdma_open,
	.prep_tc_change = irdma_prep_tc_change,
};

/**
 * irdma_probe - client interface probe operation for RDMA dev
 * @ldev: lan device information
 *
 * Called by the lan driver during the processing of client register
 * Create device resources, set up queues, pble and hmc objects.
 * Return 0 if successful, otherwise return error
 */
static int irdma_probe(struct ice_peer_dev *ldev)
{
	struct irdma_handler *hdl;
	struct irdma_pci_f *rf;
	struct irdma_sc_dev *dev;
	struct irdma_priv_ldev *pldev;

	pr_info("probe: ldev=%p, ldev->dev.pdev.bus->number=%d, ldev->netdev=%p\n",
		ldev, ldev->pdev->bus->number, ldev->netdev);
	hdl = irdma_find_handler(ldev->pdev);
	if (hdl)
		return -EBUSY;

	hdl = kzalloc(sizeof(*hdl), GFP_KERNEL);
	if (!hdl)
		return IRDMA_ERR_NO_MEMORY;

	rf = &hdl->rf;
	pldev = &rf->ldev;
	hdl->ldev = pldev;
	rf->hdl = hdl;
	dev = &rf->sc_dev;
	dev->back_dev = rf;
	rf->init_hw = icrdma_init_hw;
	pldev->if_ldev = ldev;
	rf->rdma_ver = IRDMA_GEN_2;
	irdma_init_rf_params(rf);
	if (rf->roce_ena & (1 << ldev->index))
		rf->protocol_used = IRDMA_ROCE_PROTOCOL_ONLY;
	else
		rf->protocol_used = IRDMA_IWARP_PROTOCOL_ONLY;
	dev->pci_rev = ldev->pdev->revision;
	rf->default_vsi.vsi_idx = ldev->pf_vsi_num;
	/* save information from ldev to priv_ldev*/
	pldev->fn_num = ldev->fn_num;
	rf->hw.hw_addr = ldev->hw_addr;
	rf->pdev = ldev->pdev;
	rf->netdev = ldev->netdev;
	pldev->ftype = ldev->ftype;
	pldev->msix_count = ldev->msix_count;
	pldev->msix_entries = ldev->msix_entries;
	irdma_add_handler(hdl);
	if (irdma_ctrl_init_hw(rf)) {
		irdma_del_handler(hdl);
		kfree(hdl);
		return -EIO;
	}
	ldev->peer_ops = &irdma_peer_ops;

	irdma_probe_inc_ref(ldev->netdev);

	return 0;
}

static struct ice_peer_drv irdma_client = {
	.dev_id.device = ICE_PEER_RDMA_DEV,
	.dev_id.vendor = PCI_VENDOR_ID_INTEL,
	.driver.mod_name = "irdma",
	.driver.name = "irdma",
	.driver.owner = THIS_MODULE,
	.driver_id = ICE_PEER_RDMA_DRIVER,
	.name = KBUILD_MODNAME,
	.probe = irdma_probe,
	.remove = irdma_remove,
	.ver.major = ICE_PEER_MAJOR_VER,
	.ver.minor = ICE_PEER_MINOR_VER,

};

/**
 * icrdma_request_reset - Request a reset
 * @rf: RDMA PCI function
 *
 */
void icrdma_request_reset(struct irdma_pci_f *rf)
{
	struct ice_peer_dev *ldev = (struct ice_peer_dev *)rf->ldev.if_ldev;

	if (ldev && ldev->ops && ldev->ops->request_reset)
		ldev->ops->request_reset(ldev, ICE_PEER_PFR);
}

int icrdma_reg_peer_driver(struct irdma_peer *peer, struct net_device *netdev)
{
	struct idc_srv_provider *sp;

	sp = (struct idc_srv_provider *)netdev_priv(netdev);
	if (sp->signature != IDC_SIGNATURE)
		return -EINVAL;

	peer->reg_peer_driver = (int (*)(void *))sp->reg_peer_driver;
	peer->unreg_peer_driver = (int (*)(void *))sp->unreg_peer_driver;

	return peer->reg_peer_driver(&irdma_client);
}

void icrdma_unreg_peer_driver(struct irdma_peer *peer)
{
	peer->unreg_peer_driver(&irdma_client);
}
