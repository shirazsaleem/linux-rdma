// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2019, Intel Corporation. */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/addrconf.h>
#include "main.h"
#include "i40iw_hw.h"
#include "i40e_client.h"
#define CLIENT_IW_INTERFACE_VERSION_MAJOR 0
#define CLIENT_IW_INTERFACE_VERSION_MINOR 01
#define CLIENT_IW_INTERFACE_VERSION_BUILD 00

/**
 * i40iw_request_reset - Request a reset
 * @rf: RDMA PCI function
 *
 */
void i40iw_request_reset(struct irdma_pci_f *rf)
{
	struct i40e_info *ldev = (struct i40e_info *)rf->ldev.if_ldev;

	ldev->ops->request_reset(ldev, rf->ldev.if_client, 1);
}

/**
 * i40iw_open - client interface operation open for iwarp/uda device
 * @ldev: lan device information
 * @client: iwarp client information, provided during registration
 *
 * Called by the lan driver during the processing of client register
 * Create device resources, set up queues, pble and hmc objects and
 * register the device with the ib verbs interface
 * Return 0 if successful, otherwise return error
 */
static int i40iw_open(struct i40e_info *ldev, struct i40e_client *client)
{
	struct irdma_device *iwdev = NULL;
	struct irdma_handler *hdl = NULL;
	struct irdma_priv_ldev *pldev;
	struct irdma_sc_dev *dev;
	struct irdma_pci_f *rf;
	struct irdma_l2params l2params = {};
	int err_code = -EIO;
	int i;
	u16 qset;
	u16 last_qset = IRDMA_NO_QSET;

	hdl = irdma_find_handler(ldev->pcidev);
	if (hdl)
		return 0;

	hdl = kzalloc((sizeof(*hdl) + sizeof(*iwdev)), GFP_KERNEL);
	if (!hdl)
		return -ENOMEM;

	iwdev = (struct irdma_device *)((u8 *)hdl + sizeof(*hdl));

	iwdev->param_wq = alloc_ordered_workqueue("l2params", WQ_MEM_RECLAIM);
	if (!iwdev->param_wq)
		goto error;

	rf = &hdl->rf;
	rf->hdl = hdl;
	dev = &rf->sc_dev;
	dev->back_dev = rf;
	rf->rdma_ver = IRDMA_GEN_1;
	irdma_init_rf_params(rf);
	rf->init_hw = i40iw_init_hw;
	rf->hw.hw_addr = ldev->hw_addr;
	rf->pdev = ldev->pcidev;
	rf->netdev = ldev->netdev;
	dev->pci_rev = rf->pdev->revision;
	iwdev->rf = rf;
	iwdev->hdl = hdl;
	iwdev->ldev = &rf->ldev;
	iwdev->init_state = INITIAL_STATE;
	iwdev->rcv_wnd = IRDMA_CM_DEFAULT_RCV_WND_SCALED;
	iwdev->rcv_wscale = IRDMA_CM_DEFAULT_RCV_WND_SCALE;
	iwdev->netdev = ldev->netdev;
	iwdev->create_ilq = true;
	iwdev->vsi_num = 0;

	pldev = &rf->ldev;
	hdl->ldev = pldev;
	pldev->if_client = client;
	pldev->if_ldev = ldev;
	pldev->fn_num = ldev->fid;
	pldev->ftype = ldev->ftype;
	pldev->pf_vsi_num = 0;
	pldev->msix_count = ldev->msix_count;
	pldev->msix_entries = ldev->msix_entries;

	if (irdma_ctrl_init_hw(rf))
		goto error;

	l2params.mtu =
		(ldev->params.mtu) ? ldev->params.mtu : IRDMA_DEFAULT_MTU;
	for (i = 0; i < I40E_CLIENT_MAX_USER_PRIORITY; i++) {
		qset = ldev->params.qos.prio_qos[i].qs_handle;
		l2params.up2tc[i] = ldev->params.qos.prio_qos[i].tc;
		l2params.qs_handle_list[i] = qset;
		if (last_qset == IRDMA_NO_QSET)
			last_qset = qset;
		else if ((qset != last_qset) && (qset != IRDMA_NO_QSET))
			iwdev->dcb = true;
	}

	if (irdma_rt_init_hw(rf, iwdev, &l2params)) {
		irdma_deinit_ctrl_hw(rf);
		goto error;
	}

	irdma_add_handler(hdl);
	irdma_probe_inc_ref(ldev->netdev);
	return 0;
error:
	kfree(hdl);
	return err_code;
}

/**
 * i40iw_l2params_worker - worker for l2 params change
 * @work: work pointer for l2 params
 */
static void i40iw_l2params_worker(struct work_struct *work)
{
	struct l2params_work *dwork =
		container_of(work, struct l2params_work, work);
	struct irdma_device *iwdev = dwork->iwdev;

	irdma_change_l2params(&iwdev->vsi, &dwork->l2params);
	atomic_dec(&iwdev->params_busy);
	kfree(work);
}

/**
 * i40iw_l2param_change - handle qs handles for qos and mss change
 * @ldev: lan device information
 * @client: client for parameter change
 * @params: new parameters from L2
 */
static void i40iw_l2param_change(struct i40e_info *ldev,
				 struct i40e_client *client,
				 struct i40e_params *params)
{
	struct irdma_handler *hdl;
	struct irdma_l2params *l2params;
	struct l2params_work *work;
	struct irdma_device *iwdev;
	int i;

	hdl = irdma_find_handler(ldev->pcidev);
	if (!hdl)
		return;

	iwdev = (struct irdma_device *)((u8 *)hdl + sizeof(*hdl));

	if (atomic_read(&iwdev->params_busy))
		return;
	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return;

	atomic_inc(&iwdev->params_busy);
	work->iwdev = iwdev;
	l2params = &work->l2params;
	for (i = 0; i < I40E_CLIENT_MAX_USER_PRIORITY; i++)
		l2params->qs_handle_list[i] = params->qos.prio_qos[i].qs_handle;

	l2params->mtu = (params->mtu) ? params->mtu : iwdev->vsi.mtu;

	INIT_WORK(&work->work, i40iw_l2params_worker);
	queue_work(iwdev->param_wq, &work->work);
}

/**
 * i40iw_close - client interface operation close for iwarp/uda device
 * @ldev: lan device information
 * @client: client to close
 * @reset: flag to indicate close on reset
 *
 * Called by the lan driver during the processing of client unregister
 * Destroy and clean up the driver resources
 */
static void i40iw_close(struct i40e_info *ldev, struct i40e_client *client,
			bool reset)
{
	struct irdma_handler *hdl;
	struct irdma_pci_f *rf;
	struct irdma_device *iwdev;

	hdl = irdma_find_handler(ldev->pcidev);
	if (!hdl)
		return;
	rf = &hdl->rf;
	iwdev = (struct irdma_device *)((u8 *)hdl + sizeof(*hdl));

	if (iwdev->param_wq)
		destroy_workqueue(iwdev->param_wq);

	if (reset)
		iwdev->reset = true;

	irdma_deinit_rt_device(iwdev);
	irdma_deinit_ctrl_hw(rf);
	irdma_del_handler(irdma_find_handler(ldev->pcidev));
	kfree(hdl);
	irdma_probe_dec_ref(ldev->netdev);
	pr_info("IRDMA hardware deinitialization complete\n");
}

/* client interface functions */
static const struct i40e_client_ops i40e_ops = {
	.open = i40iw_open,
	.close = i40iw_close,
	.l2_param_change = i40iw_l2param_change
};

static struct i40e_client i40iw_client = {
	.version.major = CLIENT_IW_INTERFACE_VERSION_MAJOR,
	.version.minor = CLIENT_IW_INTERFACE_VERSION_MINOR,
	.version.build = CLIENT_IW_INTERFACE_VERSION_BUILD,
	.ops = &i40e_ops,
	.name = "irdma",
	.type = I40E_CLIENT_IWARP,
};

int i40iw_reg_peer_driver(struct irdma_peer *peer, struct net_device *netdev)
{
	struct idc_srv_provider *sp;

	sp = (struct idc_srv_provider *)netdev_priv(netdev);
	if (sp->signature != IDC_SIGNATURE)
		return -EINVAL;

	peer->reg_peer_driver = (int (*)(void *))sp->reg_peer_driver;
	peer->unreg_peer_driver = (int (*)(void *))sp->unreg_peer_driver;

	return peer->reg_peer_driver(&i40iw_client);
}

void i40iw_unreg_peer_driver(struct irdma_peer *peer)
{
	peer->unreg_peer_driver(&i40iw_client);
}
