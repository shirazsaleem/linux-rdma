// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018, Intel Corporation. */

/* Inter-Driver Communication */
#include "ice.h"
#include "ice_lib.h"
#include "ice_dcb_lib.h"

DEFINE_IDA(ice_peer_index_ida);
DEFINE_MUTEX(ice_peer_drv_mutex); /* lock for accessing list of peer drivers */
LIST_HEAD(ice_peer_drv_list);

const struct peer_dev_id peer_dev_ids[] = {
	{ ICE_PEER_RDMA_NAME, ICE_PEER_RDMA_DEV },
};

/**
 * ice_validate_peer_dev - validate peer device state
 * @peer_dev: ptr to peer device
 *
 * This helper function checks if PF is in a minimal state and if the peer
 * device is valid. This should be called before engaging in peer operations.
 *
 * Returns true if the peer device is valid, false otherwise.
 */
bool ice_validate_peer_dev(struct ice_peer_dev *peer_dev)
{
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_pf *pf;

	if (!peer_dev || !peer_dev->pdev)
		return false;

	if (!peer_dev->peer_ops)
		return false;

	pf = pci_get_drvdata(peer_dev->pdev);
	if (!pf)
		return false;

	peer_dev_int = peer_to_ice_dev_int(peer_dev);
	if (!peer_dev_int)
		return false;

	if (test_bit(ICE_PEER_DEV_STATE_REMOVED, peer_dev_int->state))
		return false;

	return true;
}

/**
 * ice_peer_state_change - manage state machine for peer
 * @peer_dev: pointer to peer's configuration
 * @new_state: the state requested to transition into
 * @locked: boolean to determine if call made with mutex held
 *
 * This function handles all state transitions for peer devices.
 * The state machine is as follows:
 *
 *     +<-----------------------+<-----------------------------+
 *				|	 +<----------+	       +
 *				\/	 +	     +	       +
 *    INIT  --------------> PROBED --> OPENING	  CLOSED --> REMOVED
 *					 +           +
 *				       OPENED --> CLOSING
 *					 +	     +
 *				       PREP_RST	     +
 *					 +	     +
 *				      PREPPED	     +
 *					 +---------->+
 */
static void
ice_peer_state_change(struct ice_peer_dev_int *peer_dev, long new_state,
		      bool locked)
{
	if (!locked)
		mutex_lock(&peer_dev->peer_dev_state_mutex);

	switch (new_state) {
	case ICE_PEER_DEV_STATE_INIT:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_REMOVED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_INIT, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _REMOVED to _INIT\n");
		} else {
			set_bit(ICE_PEER_DEV_STATE_INIT, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state set to _INIT\n");
		}
		break;
	case ICE_PEER_DEV_STATE_PROBED:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_INIT,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_PROBED, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _INIT to _PROBED\n");
		} else if (test_and_clear_bit(ICE_PEER_DEV_STATE_REMOVED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_PROBED, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _REMOVED to _PROBED\n");
		}
		break;
	case ICE_PEER_DEV_STATE_OPENING:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_PROBED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_OPENING, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _PROBED to _OPENING\n");
		} else if (test_and_clear_bit(ICE_PEER_DEV_STATE_CLOSED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_OPENING, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _CLOSED to _OPENING\n");
		}
		break;
	case ICE_PEER_DEV_STATE_OPENED:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_OPENING,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_OPENED, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _OPENING to _OPENED\n");
		}
		break;
	case ICE_PEER_DEV_STATE_PREP_RST:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_OPENED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_PREP_RST, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _OPENED to _PREP_RST\n");
		}
		break;
	case ICE_PEER_DEV_STATE_PREPPED:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_PREP_RST,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_PREPPED, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition _PREP_RST to _PREPPED\n");
		}
		break;
	case ICE_PEER_DEV_STATE_CLOSING:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_OPENED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_CLOSING, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _OPENED to _CLOSING\n");
		}
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_PREPPED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_CLOSING, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition _PREPPED to _CLOSING\n");
		}
		/* NOTE - up to peer to handle this situation correctly */
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_PREP_RST,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_CLOSING, peer_dev->state);
			dev_warn(&peer_dev->peer_dev.platform_dev.dev,
				 "WARN: Peer state PREP_RST to _CLOSING\n");
		}
		break;
	case ICE_PEER_DEV_STATE_CLOSED:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_CLOSING,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_CLOSED, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state transition from _CLOSING to _CLOSED\n");
		}
		break;
	case ICE_PEER_DEV_STATE_REMOVED:
		if (test_and_clear_bit(ICE_PEER_DEV_STATE_OPENED,
				       peer_dev->state) ||
		    test_and_clear_bit(ICE_PEER_DEV_STATE_CLOSED,
				       peer_dev->state)) {
			set_bit(ICE_PEER_DEV_STATE_REMOVED, peer_dev->state);
			dev_info(&peer_dev->peer_dev.platform_dev.dev,
				 "state from _OPENED/_CLOSED to _REMOVED\n");
			/* Clear registration for events when peer removed */
			bitmap_zero(peer_dev->events, ICE_PEER_DEV_STATE_NBITS);
		}
		break;
	default:
		break;
	}

	if (!locked)
		mutex_unlock(&peer_dev->peer_dev_state_mutex);
}

/**
 * ice_peer_close - close a peer device
 * @peer_dev_int: device to close
 * @data: pointer to opaque data
 *
 * This function will also set the state bit for the peer to CLOSED. This
 * function is meant to be called from a bus_for_each_dev().
 */
int ice_peer_close(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	enum ice_close_reason reason = *(enum ice_close_reason *)(data);
	struct ice_peer_dev *peer_dev = &peer_dev_int->peer_dev;
	struct ice_pf *pf;
	int i;

	/* return 0 so bus_for_each_device will continue closing other peers */
	if (!ice_validate_peer_dev(peer_dev))
		return 0;
	pf = pci_get_drvdata(peer_dev->pdev);

	if (test_bit(__ICE_DOWN, pf->state) ||
	    test_bit(__ICE_SUSPENDED, pf->state) ||
	    test_bit(__ICE_NEEDS_RESTART, pf->state))
		return 0;

	mutex_lock(&peer_dev_int->peer_dev_state_mutex);

	/* no peer driver, already closed, closing or opening nothing to do */
	if (test_bit(ICE_PEER_DEV_STATE_CLOSED, peer_dev_int->state) ||
	    test_bit(ICE_PEER_DEV_STATE_CLOSING, peer_dev_int->state) ||
	    test_bit(ICE_PEER_DEV_STATE_OPENING, peer_dev_int->state) ||
	    test_bit(ICE_PEER_DEV_STATE_REMOVED, peer_dev_int->state))
		goto peer_close_out;

	/* Set the peer state to CLOSING */
	ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_CLOSING, true);

	for (i = 0; i < ICE_EVENT_NBITS; i++)
		bitmap_zero(peer_dev_int->current_events[i].type,
			    ICE_EVENT_NBITS);

	if (peer_dev->peer_ops && peer_dev->peer_ops->close)
		peer_dev->peer_ops->close(peer_dev, reason);

	/* Set the peer state to CLOSED */
	ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_CLOSED, true);

peer_close_out:
	mutex_unlock(&peer_dev_int->peer_dev_state_mutex);

	return 0;
}

/**
 * ice_close_peer_for_reset - queue work to close peer for reset
 * @peer_dev_int: pointer peer dev internal struct
 * @data: pointer to opaque data used for reset type
 */
int ice_close_peer_for_reset(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	struct ice_peer_dev *peer_dev = &peer_dev_int->peer_dev;
	enum ice_reset_req reset;

	if (!ice_validate_peer_dev(peer_dev))
		return 0;

	reset = *(enum ice_reset_req *)data;

	switch (reset) {
	case ICE_RESET_GLOBR:
		peer_dev_int->rst_type = ICE_REASON_GLOBR_REQ;
		break;
	case ICE_RESET_CORER:
		peer_dev_int->rst_type = ICE_REASON_CORER_REQ;
		break;
	case ICE_RESET_PFR:
		peer_dev_int->rst_type = ICE_REASON_PFR_REQ;
		break;
	default:
		/* reset type is invalid */
		return 1;
	}
	queue_work(peer_dev_int->ice_peer_wq, &peer_dev_int->peer_close_task);
	return 0;
}

/**
 * ice_check_peer_drv_for_events - check peer_drv for events to report
 * @peer_dev: peer device to report to
 */
static void ice_check_peer_drv_for_events(struct ice_peer_dev *peer_dev)
{
	const struct ice_peer_ops *p_ops = peer_dev->peer_ops;
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_peer_drv_int *peer_drv_int;
	struct ice_peer_drv *peer_drv;
	int i;

	peer_drv = peer_dev->peer_drv;
	peer_dev_int = peer_to_ice_dev_int(peer_dev);
	peer_drv_int = peer_to_ice_drv_int(peer_drv);

	for_each_set_bit(i, peer_dev_int->events, ICE_EVENT_NBITS) {
		struct ice_event *curr = &peer_drv_int->current_events[i];

		if (!bitmap_empty(curr->type, ICE_EVENT_NBITS) &&
		    p_ops->event_handler)
			p_ops->event_handler(peer_dev, curr);
	}
}

/**
 * ice_check_peer_for_events - check peer_devs for events new peer reg'd for
 * @src_peer_int: peer to check for events
 * @data: ptr to opaque data, to be used for the peer struct that opened
 *
 * This function is to be called when a peer device is opened.
 *
 * Since a new peer opening would have missed any events that would
 * have happened before its opening, we need to walk the peers and see
 * if any of them have events that the new peer cares about
 *
 * This function is meant to be called by a device_for_each_child.
 */
static int ice_check_peer_for_events(struct ice_peer_dev_int *src_peer_int,
				     void *data)
{
	struct ice_peer_dev *new_peer = (struct ice_peer_dev *)data;
	struct ice_peer_dev *src_peer = &src_peer_int->peer_dev;
	const struct ice_peer_ops *p_ops = new_peer->peer_ops;
	struct ice_peer_dev_int *new_peer_int;
	int i;

	if (!ice_validate_peer_dev(new_peer) ||
	    !ice_validate_peer_dev(src_peer))
		return 0;

	new_peer_int = peer_to_ice_dev_int(new_peer);

	for_each_set_bit(i, new_peer_int->events, ICE_EVENT_NBITS) {
		struct ice_event *curr = &src_peer_int->current_events[i];

		if (!bitmap_empty(curr->type, ICE_EVENT_NBITS) &&
		    new_peer->index != src_peer->index &&
		    p_ops->event_handler)
			p_ops->event_handler(new_peer, curr);
	}

	return 0;
}

/**
 * ice_for_each_peer - iterate across and call function for each peer dev
 * @pf: pointer to private board struct
 * @data: data to pass to function on each call
 * @fn: pointer to function to call for each peer
 *
 * This function is to be used similarly to bus_for_each_dev
 */
int ice_for_each_peer(struct ice_pf *pf, void *data,
		      int (*fn)(struct ice_peer_dev_int *, void *))
{
	struct ice_peer_dev_int *peer_dev_int;
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(peer_dev_ids); i++) {
		peer_dev_int = pf->peers[i];
		if (peer_dev_int) {
			ret = fn(peer_dev_int, data);
			if (ret)
				break;
		}
	}

	return ret;
}

/**
 * ice_finish_init_peer_device - complete peer device initialization
 * @peer_dev_int: ptr to peer device internal struct
 * @data: ptr to opaque data
 *
 * This function completes remaining initialization of peer_devices
 */
int ice_finish_init_peer_device(struct ice_peer_dev_int *peer_dev_int,
				void __always_unused *data)
{
	struct ice_peer_dev *peer_dev = &peer_dev_int->peer_dev;
	struct ice_peer_drv *peer_drv;
	struct ice_pf *pf;
	int ret = 0;

	/* peer_dev will not always be populated at the time of this check */
	if (!ice_validate_peer_dev(peer_dev))
		return ret;

	peer_drv = peer_dev->peer_drv;
	pf = pci_get_drvdata(peer_dev->pdev);
	/* There will be several assessments of the peer_dev's state in this
	 * chunk of logic.  We need to hold the peer_dev_int's state mutex
	 * for the entire part so that the flow progresses without another
	 * context changing things mid-flow
	 */
	mutex_lock(&peer_dev_int->peer_dev_state_mutex);

	if (!peer_dev->peer_ops) {
		dev_err(&pf->pdev->dev,
			"peer_ops not defined on peer dev\n");
		goto init_unlock;
	}

	if (!peer_dev->peer_ops->open) {
		dev_err(&pf->pdev->dev,
			"peer_ops:open not defined on peer dev\n");
		goto init_unlock;
	}

	if (!peer_dev->peer_ops->close) {
		dev_err(&pf->pdev->dev,
			"peer_ops:close not defined on peer dev\n");
		goto init_unlock;
	}

	/* Peer driver expected to set driver_id during registration */
	if (!peer_drv->driver_id) {
		dev_err(&pf->pdev->dev,
			"Peer driver did not set driver_id\n");
		goto init_unlock;
	}

	if ((test_bit(ICE_PEER_DEV_STATE_CLOSED, peer_dev_int->state) ||
	     test_bit(ICE_PEER_DEV_STATE_PROBED, peer_dev_int->state)) &&
	    ice_pf_state_is_nominal(pf)) {
		ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_OPENING,
				      true);
		peer_dev->peer_ops->open(peer_dev);
		ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_OPENED,
				      true);
		ret = ice_for_each_peer(pf, peer_dev,
					ice_check_peer_for_events);
		ice_check_peer_drv_for_events(peer_dev);
	}

init_unlock:
	mutex_unlock(&peer_dev_int->peer_dev_state_mutex);

	return ret;
}

/**
 * ice_unreg_peer_device - unregister specified device
 * @peer_dev_int: ptr to peer device internal
 * @data: ptr to opaque data
 *
 * This function invokes device unregistration, removes ID associated with
 * the specified device.
 */
int ice_unreg_peer_device(struct ice_peer_dev_int *peer_dev_int,
			  void __always_unused *data)
{
	platform_device_unregister(&peer_dev_int->peer_dev.platform_dev);

	/* Don't need additional validity checks here - these are really just
	 * container_of calls so if dev is valid, peer_dev_int will be valid
	 * as well.
	 */
	if (peer_dev_int->ice_peer_wq) {
		if (peer_dev_int->peer_prep_task.func)
			cancel_work_sync(&peer_dev_int->peer_prep_task);

		if (peer_dev_int->peer_close_task.func)
			cancel_work_sync(&peer_dev_int->peer_close_task);
		destroy_workqueue(peer_dev_int->ice_peer_wq);
	}

	/* Cleanup the allocated ID for this peer device */
	ida_simple_remove(&ice_peer_index_ida, peer_dev_int->peer_dev.index);

	devm_kfree(&peer_dev_int->peer_dev.pdev->dev, peer_dev_int);

	return 0;
}

/**
 * ice_unroll_peer - destroy peers and peer_wq in case of error
 * @peer_dev_int: ptr to peer device internal struct
 * @data: ptr to opaque data
 *
 * This function releases resources in the event of a failure in creating
 * peer devices or their individual work_queues. Meant to be called from
 * a bus_for_each_device invocation
 */
int ice_unroll_peer(struct ice_peer_dev_int *peer_dev_int,
		    void __always_unused *data)
{
	struct ice_pf *pf;

	pf = pci_get_drvdata(peer_dev_int->peer_dev.pdev);

	if (peer_dev_int->ice_peer_wq)
		destroy_workqueue(peer_dev_int->ice_peer_wq);
	devm_kfree(&pf->pdev->dev, peer_dev_int);

	return 0;
}

/**
 * ice_find_vsi - Find the VSI from VSI ID
 * @pf: The PF pointer to search in
 * @vsi_num: The VSI ID to search for
 */
static struct ice_vsi *ice_find_vsi(struct ice_pf *pf, u16 vsi_num)
{
	int i;

	ice_for_each_vsi(pf, i)
		if (pf->vsi[i] && pf->vsi[i]->vsi_num == vsi_num)
			return  pf->vsi[i];
	return NULL;
}

/**
 * ice_peer_alloc_rdma_qsets - Allocate Leaf Nodes for RDMA Qset
 * @peer_dev: peer that is requesting the Leaf Nodes
 * @res: Resources to be allocated
 * @partial_acceptable: If partial allocation is acceptable to the peer
 *
 * This function allocates Leaf Nodes for given RDMA Qset resources
 * for the peer device.
 */
static int
ice_peer_alloc_rdma_qsets(struct ice_peer_dev *peer_dev, struct ice_res *res,
			  int __maybe_unused partial_acceptable)
{
	u16 max_rdmaqs[ICE_MAX_TRAFFIC_CLASS];
	enum ice_status status;
	struct ice_vsi *vsi;
	struct ice_pf *pf;
	int i, ret = 0;
	u32 *qset_teid;
	u16 *qs_handle;

	if (!ice_validate_peer_dev(peer_dev) || !res)
		return -EINVAL;

	pf = pci_get_drvdata(peer_dev->pdev);

	if (res->cnt_req > ICE_MAX_TXQ_PER_TXQG)
		return -EINVAL;

	qset_teid = devm_kcalloc(&pf->pdev->dev, res->cnt_req,
				 sizeof(*qset_teid), GFP_KERNEL);
	if (!qset_teid)
		return -ENOMEM;

	qs_handle = devm_kcalloc(&pf->pdev->dev, res->cnt_req,
				 sizeof(*qs_handle), GFP_KERNEL);
	if (!qs_handle) {
		devm_kfree(&pf->pdev->dev, qset_teid);
		return -ENOMEM;
	}

	ice_for_each_traffic_class(i)
		max_rdmaqs[i] = 0;

	for (i = 0; i < res->cnt_req; i++) {
		struct ice_rdma_qset_params *qset;

		qset = &res->res[i].res.qsets;
		if (qset->vsi_id != peer_dev->pf_vsi_num) {
			dev_err(&pf->pdev->dev,
				"RDMA QSet invalid VSI requested\n");
			ret = -EINVAL;
			goto out;
		}
		max_rdmaqs[qset->tc]++;
		qs_handle[i] = qset->qs_handle;
	}

	vsi = ice_find_vsi(pf, peer_dev->pf_vsi_num);
	if (!vsi) {
		dev_err(&pf->pdev->dev, "RDMA QSet invalid VSI\n");
		ret = -EINVAL;
		goto out;
	}

	status = ice_cfg_vsi_rdma(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				  max_rdmaqs);
	if (status) {
		dev_err(&pf->pdev->dev, "Failed VSI RDMA qset config\n");
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < res->cnt_req; i++) {
		struct ice_rdma_qset_params *qset;

		qset = &res->res[i].res.qsets;
		status = ice_ena_vsi_rdma_qset(vsi->port_info, vsi->idx,
					       qset->tc, &qs_handle[i], 1,
					       &qset_teid[i]);
		if (status) {
			dev_err(&pf->pdev->dev,
				"Failed VSI RDMA qset enable\n");
			ret = -EINVAL;
			goto out;
		}
		vsi->qset_handle[qset->tc] = qset->qs_handle;
		qset->teid = qset_teid[i];
	}

out:
	devm_kfree(&pf->pdev->dev, qset_teid);
	devm_kfree(&pf->pdev->dev, qs_handle);
	return ret;
}

/**
 * ice_peer_free_rdma_qsets - Free leaf nodes for RDMA Qset
 * @peer_dev: peer that requested qsets to be freed
 * @res: Resource to be freed
 */
static int
ice_peer_free_rdma_qsets(struct ice_peer_dev *peer_dev, struct ice_res *res)
{
	enum ice_status status;
	int count, i, ret = 0;
	struct ice_vsi *vsi;
	struct ice_pf *pf;
	u16 vsi_id;
	u32 *teid;
	u16 *q_id;

	if (!ice_validate_peer_dev(peer_dev) || !res)
		return -EINVAL;

	pf = pci_get_drvdata(peer_dev->pdev);

	count = res->res_allocated;
	if (count > ICE_MAX_TXQ_PER_TXQG)
		return -EINVAL;

	teid = devm_kcalloc(&pf->pdev->dev, count, sizeof(*teid), GFP_KERNEL);
	if (!teid)
		return -ENOMEM;

	q_id = devm_kcalloc(&pf->pdev->dev, count, sizeof(*q_id), GFP_KERNEL);
	if (!q_id) {
		devm_kfree(&pf->pdev->dev, teid);
		return -ENOMEM;
	}

	vsi_id = res->res[0].res.qsets.vsi_id;
	vsi = ice_find_vsi(pf, vsi_id);
	if (!vsi) {
		dev_err(&pf->pdev->dev, "RDMA Invalid VSI\n");
		ret = -EINVAL;
		goto rdma_free_out;
	}

	for (i = 0; i < count; i++) {
		struct ice_rdma_qset_params *qset;

		qset = &res->res[i].res.qsets;
		if (qset->vsi_id != vsi_id) {
			dev_err(&pf->pdev->dev, "RDMA Invalid VSI ID\n");
			ret = -EINVAL;
			goto rdma_free_out;
		}
		q_id[i] = qset->qs_handle;
		teid[i] = qset->teid;

		vsi->qset_handle[qset->tc] = 0;
	}

	status = ice_dis_vsi_rdma_qset(vsi->port_info, count, teid, q_id);
	if (status)
		ret = -EINVAL;

rdma_free_out:
	devm_kfree(&pf->pdev->dev, teid);
	devm_kfree(&pf->pdev->dev, q_id);

	return ret;
}

/**
 * ice_peer_alloc_res - Allocate requested resources for peer device
 * @peer_dev: peer that is requesting resources
 * @res: Resources to be allocated
 * @partial_acceptable: If partial allocation is acceptable to the peer
 *
 * This function allocates requested resources for the peer device.
 */
static int
ice_peer_alloc_res(struct ice_peer_dev *peer_dev, struct ice_res *res,
		   int partial_acceptable)
{
	struct ice_pf *pf;
	int ret;

	if (!ice_validate_peer_dev(peer_dev) || !res)
		return -EINVAL;

	pf = pci_get_drvdata(peer_dev->pdev);
	if (!ice_pf_state_is_nominal(pf))
		return -EBUSY;

	switch (res->res_type) {
	case ICE_RDMA_QSETS_TXSCHED:
		ret = ice_peer_alloc_rdma_qsets(peer_dev, res,
						partial_acceptable);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * ice_peer_free_res - Free given resources
 * @peer_dev: peer that is requesting freeing of resources
 * @res: Resources to be freed
 *
 * Free/Release resources allocated to given peer device.
 */
static int
ice_peer_free_res(struct ice_peer_dev *peer_dev, struct ice_res *res)
{
	int ret;

	if (!ice_validate_peer_dev(peer_dev) || !res)
		return -EINVAL;

	switch (res->res_type) {
	case ICE_RDMA_QSETS_TXSCHED:
		ret = ice_peer_free_rdma_qsets(peer_dev, res);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * ice_peer_reg_for_notif - register a peer to receive specific notifications
 * @peer_dev: peer that is registering for event notifications
 * @events: mask of event types peer is registering for
 */
static void
ice_peer_reg_for_notif(struct ice_peer_dev *peer_dev, struct ice_event *events)
{
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_pf *pf;

	if (!ice_validate_peer_dev(peer_dev) || !events)
		return;

	peer_dev_int = peer_to_ice_dev_int(peer_dev);
	pf = pci_get_drvdata(peer_dev->pdev);

	bitmap_or(peer_dev_int->events, peer_dev_int->events, events->type,
		  ICE_EVENT_NBITS);

	/* Check to see if any events happened previous to peer registering */
	ice_for_each_peer(pf, peer_dev, ice_check_peer_for_events);
	ice_check_peer_drv_for_events(peer_dev);
}

/**
 * ice_peer_unreg_for_notif - unreg a peer from receiving certain notifications
 * @peer_dev: peer that is unregistering from event notifications
 * @events: mask of event types peer is unregistering for
 */
static void
ice_peer_unreg_for_notif(struct ice_peer_dev *peer_dev,
			 struct ice_event *events)
{
	struct ice_peer_dev_int *peer_dev_int;

	if (!ice_validate_peer_dev(peer_dev) || !events)
		return;

	peer_dev_int = peer_to_ice_dev_int(peer_dev);

	bitmap_andnot(peer_dev_int->events, peer_dev_int->events, events->type,
		      ICE_EVENT_NBITS);
}

/**
 * ice_peer_check_for_reg - check to see if any peers are reg'd for event
 * @peer_dev_int: ptr to peer device internal struct
 * @data: ptr to opaque data, to be used for ice_event to report
 *
 * This function is to be called by device_for_each_child to handle an
 * event reported by a peer or the ice driver.
 */
int ice_peer_check_for_reg(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	struct ice_event *event = (struct ice_event *)data;
	DECLARE_BITMAP(comp_events, ICE_EVENT_NBITS);
	struct ice_peer_dev *peer_dev;
	bool check = true;

	peer_dev = &peer_dev_int->peer_dev;

	if (!ice_validate_peer_dev(peer_dev) || !data)
	/* If invalid dev, in this case return 0 instead of error
	 * because caller ignores this return value
	 */
		return 0;

	if (event->reporter)
		check = event->reporter->index != peer_dev->index;

	if (bitmap_and(comp_events, event->type, peer_dev_int->events,
		       ICE_EVENT_NBITS) &&
	    (test_bit(ICE_PEER_DEV_STATE_OPENED, peer_dev_int->state) ||
	     test_bit(ICE_PEER_DEV_STATE_PREP_RST, peer_dev_int->state) ||
	     test_bit(ICE_PEER_DEV_STATE_PREPPED, peer_dev_int->state)) &&
	    check &&
	    peer_dev->peer_ops->event_handler)
		peer_dev->peer_ops->event_handler(peer_dev, event);

	return 0;
}

/**
 * ice_peer_report_state_change - accept report of a peer state change
 * @peer_dev: peer that is sending notification about state change
 * @event: ice_event holding info on what the state change is
 *
 * We also need to parse the list of peers to see if anyone is registered
 * for notifications about this state change event, and if so, notify them.
 */
static void
ice_peer_report_state_change(struct ice_peer_dev *peer_dev,
			     struct ice_event *event)
{
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_peer_drv_int *peer_drv_int;
	struct ice_peer_drv *peer_drv;
	struct ice_pf *pf;
	int e_type, drv_event = 0;

	if (!ice_validate_peer_dev(peer_dev) || !event)
		return;

	pf = pci_get_drvdata(peer_dev->pdev);
	peer_drv = peer_dev->peer_drv;
	peer_dev_int = peer_to_ice_dev_int(peer_dev);
	peer_drv_int = peer_to_ice_drv_int(peer_drv);

	e_type = find_first_bit(event->type, ICE_EVENT_NBITS);
	if (!e_type)
		return;

	switch (e_type) {
	/* Check for peer_drv events */
	case ICE_EVENT_MBX_CHANGE:
		drv_event = 1;
		if (event->info.mbx_rdy)
			set_bit(ICE_PEER_DRV_STATE_MBX_RDY,
				peer_drv_int->state);
		else
			clear_bit(ICE_PEER_DRV_STATE_MBX_RDY,
				  peer_drv_int->state);
		break;

	/* Check for peer_dev events */
	case ICE_EVENT_API_CHANGE:
		if (event->info.api_rdy)
			set_bit(ICE_PEER_DEV_STATE_API_RDY,
				peer_dev_int->state);
		else
			clear_bit(ICE_PEER_DEV_STATE_API_RDY,
				  peer_dev_int->state);
		break;

	default:
		return;
	}

	/* store the event and state to notify any new peers opening */
	if (drv_event)
		memcpy(&peer_drv_int->current_events[e_type], event,
		       sizeof(*event));
	else
		memcpy(&peer_dev_int->current_events[e_type], event,
		       sizeof(*event));

	ice_for_each_peer(pf, event, ice_peer_check_for_reg);
}

/**
 * ice_peer_dev_uninit - request to uninitialize peer
 * @peer_dev: peer device
 *
 * This function triggers close/remove on peer_dev allowing peer
 * to uninitialize.
 */
static int ice_peer_dev_uninit(struct ice_peer_dev *peer_dev)
{
	enum ice_close_reason reason = ICE_REASON_PEER_DEV_UNINIT;
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_pf *pf;
	int ret;

	if (!ice_validate_peer_dev(peer_dev))
		return -EINVAL;

	pf = pci_get_drvdata(peer_dev->pdev);
	if (ice_is_reset_in_progress(pf->state))
		return -EBUSY;

	peer_dev_int = peer_to_ice_dev_int(peer_dev);

	ret = ice_peer_close(peer_dev_int, &reason);
	if (ret)
		return ret;

	peer_dev->peer_ops = NULL;

	ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_REMOVED, false);

	return ret;
}

/**
 * ice_peer_probe_finished - Called by peer to open communication with LAN
 * @peer_dev: ptr to peer device
 *
 * registering peer is expected to populate the ice_peerdrv->name field
 * before calling this function.
 */
static int ice_peer_probe_finished(struct ice_peer_dev *peer_dev)
{
	struct ice_peer_drv_int *peer_drv_int;
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_peer_drv *peer_drv;
	int i;

	if (!peer_dev) {
		pr_err("Failed to reg peer dev: peer_dev ptr NULL\n");
		return -EINVAL;
	}

	if (!peer_dev->pdev) {
		pr_err("Failed to reg peer dev: peer dev pdev NULL\n");
		return -EINVAL;
	}

	if (!peer_dev->peer_ops || !peer_dev->ops) {
		pr_err("Failed to reg peer dev: peer dev peer_ops/ops NULL\n");
		return -EINVAL;
	}

	peer_drv = peer_dev->peer_drv;
	if (!peer_drv) {
		pr_err("Failed to reg peer dev: peer drv NULL\n");
		return -EINVAL;
	}

	if (peer_drv->ver.major != ICE_PEER_MAJOR_VER ||
	    peer_drv->ver.minor != ICE_PEER_MINOR_VER) {
		pr_err("failed to register due to version mismatch:\n");
		pr_err("expected major ver %d, caller specified major ver %d\n",
		       ICE_PEER_MAJOR_VER, peer_drv->ver.major);
		pr_err("expected minor ver %d, caller specified minor ver %d\n",
		       ICE_PEER_MINOR_VER, peer_drv->ver.minor);
		return -EINVAL;
	}

	peer_drv_int = kzalloc(sizeof(*peer_drv_int), GFP_KERNEL);
	if (!peer_drv_int)
		return -ENOMEM;

	peer_drv_int->peer_drv = peer_drv;
	INIT_LIST_HEAD(&peer_drv_int->drv_int_list);

	mutex_lock(&ice_peer_drv_mutex);
	list_add(&peer_drv_int->drv_int_list, &ice_peer_drv_list);
	mutex_unlock(&ice_peer_drv_mutex);

	/* Initialize driver values */
	for (i = 0; i < ICE_EVENT_NBITS; i++)
		bitmap_zero(peer_drv_int->current_events[i].type,
			    ICE_EVENT_NBITS);

	peer_dev_int = peer_to_ice_dev_int(peer_dev);
	ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_PROBED, false);

	return 0;
}

/**
 * ice_peer_request_reset - accept request from peer to perform a reset
 * @peer_dev: peer device that is request a reset
 * @reset_type: type of reset the peer is requesting
 */
static int
ice_peer_request_reset(struct ice_peer_dev *peer_dev,
		       enum ice_peer_reset_type reset_type)
{
	enum ice_reset_req reset;
	struct ice_pf *pf;

	if (!ice_validate_peer_dev(peer_dev))
		return -EINVAL;

	pf = pci_get_drvdata(peer_dev->pdev);

	switch (reset_type) {
	case ICE_PEER_PFR:
		reset = ICE_RESET_PFR;
		break;
	case ICE_PEER_CORER:
		reset = ICE_RESET_CORER;
		break;
	case ICE_PEER_GLOBR:
		reset = ICE_RESET_GLOBR;
		break;
	default:
		dev_err(&pf->pdev->dev, "incorrect reset request from peer\n");
		return -EINVAL;
	}

	return ice_schedule_reset(pf, reset);
}

/**
 * ice_peer_update_vsi_filter - update filters for RDMA VSI
 * @peer_dev: pointer to RDMA peer device
 * @filter: selection of filters to enable or disable
 * @enable: bool whether to enable or disable filters
 */
static
int ice_peer_update_vsi_filter(struct ice_peer_dev *peer_dev,
			       enum ice_rdma_filter __maybe_unused filter,
			       bool enable)
{
	struct ice_pf *pf;
	int ret, v;
	u16 idx;

	if (!ice_validate_peer_dev(peer_dev))
		return -EINVAL;

	pf = pci_get_drvdata(peer_dev->pdev);

	ice_for_each_vsi(pf, v)
		if (peer_dev->pf_vsi_num == pf->vsi[v]->vsi_num) {
			idx = pf->vsi[v]->idx;
			break;
		}
	if (v >= pf->num_alloc_vsi)
		return -EINVAL;

	ret = ice_cfg_iwarp_fltr(&pf->hw, idx, enable);

	if (ret)
		dev_err(&pf->pdev->dev, "Failed to  %sable iWARP filtering\n",
			enable ? "en" : "dis");

	return ret;
}

/**
 * ice_peer_vc_send - send a virt channel message from RDMA peer
 * @peer_dev: pointer to RDMA peer dev
 * @vf_id: the absolute VF ID of recipient of message
 * @msg: pointer to message contents
 * @len: len of message
 */
static
int ice_peer_vc_send(struct ice_peer_dev *peer_dev, u32 vf_id, u8 *msg, u16 len)
{
	struct ice_pf *pf;
	int err;

	if (!ice_validate_peer_dev(peer_dev))
		return -EINVAL;
	if (!msg || !len)
		return -ENOMEM;

	pf = pci_get_drvdata(peer_dev->pdev);
	if (vf_id >= pf->num_alloc_vfs || len > ICE_AQ_MAX_BUF_LEN)
		return -EINVAL;

	/* VIRTCHNL_OP_IWARP is being used for RoCEv2 msg also */
	err = ice_aq_send_msg_to_vf(&pf->hw, vf_id, VIRTCHNL_OP_IWARP, 0, msg,
				    len, NULL);
	if (err)
		dev_err(&pf->pdev->dev,
			"Unable to send RDMA msg to VF, error %d\n", err);

	return err;
}

/* Initialize the ice_ops struct, which is used in 'ice_init_peer_devices' */
static const struct ice_ops ops = {
	.alloc_res			= ice_peer_alloc_res,
	.free_res			= ice_peer_free_res,
	.reg_for_notification		= ice_peer_reg_for_notif,
	.unreg_for_notification		= ice_peer_unreg_for_notif,
	.notify_state_change		= ice_peer_report_state_change,
	.request_reset			= ice_peer_request_reset,
	.probe_finished			= ice_peer_probe_finished,
	.request_uninit			= ice_peer_dev_uninit,
	.update_vsi_filter		= ice_peer_update_vsi_filter,
	.vc_send			= ice_peer_vc_send,

};

/**
 * ice_reserve_peer_qvector - Reserve vector resources for peer drivers
 * @pf: board private structure to initialize
 */
static int ice_reserve_peer_qvector(struct ice_pf *pf)
{
	if (test_bit(ICE_FLAG_IWARP_ENA, pf->flags)) {
		int index;

		index = ice_get_res(pf, pf->irq_tracker, pf->num_rdma_msix,
				    ICE_RES_RDMA_VEC_ID);
		if (index < 0)
			return index;
		pf->num_avail_sw_msix -= pf->num_rdma_msix;
		pf->rdma_base_vector = index;
	}
	return 0;
}

/**
 * ice_peer_close_task - call peer's close asynchronously
 * @work: pointer to work_struct contained by the peer_dev_int struct
 *
 * This method (asynchronous) of calling a peer's close function is
 * meant to be used in the reset path.
 */
static void ice_peer_close_task(struct work_struct *work)
{
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_peer_dev *peer_dev;

	peer_dev_int = container_of(work, struct ice_peer_dev_int,
				    peer_close_task);
	if (!peer_dev_int)
		return;

	peer_dev = &peer_dev_int->peer_dev;
	if (!peer_dev || !peer_dev->peer_ops)
		return;

	/* If this peer_dev is going to close, we do not want any state changes
	 * to happen until after we successfully finish or abort the close.
	 * Grab the peer_dev_state_mutex to protect this flow
	 */
	mutex_lock(&peer_dev_int->peer_dev_state_mutex);

	ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_CLOSING, true);

	if (peer_dev->peer_ops->close)
		peer_dev->peer_ops->close(peer_dev, peer_dev_int->rst_type);

	ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_CLOSED, true);

	mutex_unlock(&peer_dev_int->peer_dev_state_mutex);
}

/**
 * ice_peer_device_release - release function for platform peer device
 * @dev: pointer to device structure
 *
 * This callback function is accessed by platform bus infrastructure when
 * all references on the peer platform device we registered are removed
 * (e.g. the peer priver has been removed).  We will use this opportunity
 * to set the peer's state to init to be ready if the peer driver re-loads.
 */
void ice_peer_device_release(struct device *dev)
{
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_peer_dev *peer_dev;

	peer_dev = dev_to_ice_peer(dev);
	peer_dev_int = container_of(peer_dev, struct ice_peer_dev_int,
				    peer_dev);

	ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_INIT, false);
}

/**
 * ice_init_peer_devices - initializes peer devices
 * @pf: ptr to ice_pf
 *
 * This function initializes peer devices and associates them with specified
 * pci_dev as their parent.
 */
int ice_init_peer_devices(struct ice_pf *pf)
{
	struct pci_dev *pdev = pf->pdev;
	struct msix_entry *entry = NULL;
	struct ice_port_info *port_info;
	struct ice_vsi *vsi;
	int status = 0;
	int i;

	/* Reserve vector resources */
	status = ice_reserve_peer_qvector(pf);
	if (status < 0) {
		dev_err(&pdev->dev,
			"failed to reserve vectors for peer drivers\n");
		return status;
	}
	for (i = 0; i < ARRAY_SIZE(peer_dev_ids); i++) {
		struct ice_peer_dev_int *peer_dev_int;
		struct platform_device *platform_dev;
		struct ice_qos_params *qos_info;
		struct ice_peer_dev *peer_dev;
		int j;

		peer_dev_int = devm_kzalloc(&pdev->dev, sizeof(*peer_dev_int),
					    GFP_KERNEL);
		if (!peer_dev_int)
			return -ENOMEM;
		pf->peers[i] = peer_dev_int;

		mutex_init(&peer_dev_int->peer_dev_state_mutex);

		peer_dev = &peer_dev_int->peer_dev;
		peer_dev->peer_ops = NULL;
		peer_dev->hw_addr = (u8 __iomem *)pf->hw.hw_addr;
		peer_dev->ver.major = ICE_PEER_MAJOR_VER;
		peer_dev->ver.minor = ICE_PEER_MINOR_VER;
		peer_dev->ver.support = ICE_IDC_FEATURES;
		peer_dev->peer_dev_id = peer_dev_ids[i].id;
		port_info = pf->hw.port_info;
		vsi = pf->vsi[0];
		peer_dev->pf_vsi_num = vsi->vsi_num;
		peer_dev->netdev = vsi->netdev;
		peer_dev->initial_mtu = vsi->netdev->mtu;
		ether_addr_copy(peer_dev->lan_addr, port_info->mac.lan_addr);

		platform_dev = &peer_dev->platform_dev;
		platform_dev->name = peer_dev_ids[i].name;
		platform_dev->id = PLATFORM_DEVID_AUTO;
		platform_dev->id_auto = true;
		platform_dev->dev.release = ice_peer_device_release;
		peer_dev_int->ice_peer_wq =
			alloc_ordered_workqueue("ice_peer_wq_%d", WQ_UNBOUND,
						i);
		if (!peer_dev_int->ice_peer_wq)
			return -ENOMEM;
		INIT_WORK(&peer_dev_int->peer_close_task, ice_peer_close_task);

		/* Assign a unique index and hence name for peer device */
		status = ida_simple_get(&ice_peer_index_ida, 0, 0, GFP_KERNEL);
		if (status < 0) {
			dev_err(&pdev->dev,
				"failed to get unique index for device\n");
			devm_kfree(&pdev->dev, peer_dev);
			return status;
		}
		peer_dev->index = status;
		peer_dev->pdev = pdev;
		peer_dev->ari_ena = pci_ari_enabled(pdev->bus);
		peer_dev->bus_num = PCI_BUS_NUM(pdev->devfn);
		if (!peer_dev->ari_ena) {
			peer_dev->dev_num = PCI_SLOT(pdev->devfn);
			peer_dev->fn_num = PCI_FUNC(pdev->devfn);
		} else {
			peer_dev->dev_num = 0;
			peer_dev->fn_num = pdev->devfn & 0xff;
		}

		qos_info = &peer_dev->initial_qos_info;

		/* setup qos_info fields with defaults */
		qos_info->num_apps = 0;
		qos_info->num_tc = 1;

		for (j = 0; j < ICE_IDC_MAX_USER_PRIORITY; j++)
			qos_info->up2tc[j] = 0;

		qos_info->tc_info[0].rel_bw = 100;
		for (j = 1; j < IEEE_8021QAZ_MAX_TCS; j++)
			qos_info->tc_info[j].rel_bw = 0;

#ifdef CONFIG_DCB
		/* for DCB, override the qos_info defaults. */
		ice_setup_dcb_qos_info(pf, qos_info);

#endif /* CONFIG_DCB */
		/* Initialize ice_ops */
		peer_dev->ops = &ops;

		/* make sure peer specific resources such as msix_count and
		 * msix_entries are initialized
		 */
		switch (peer_dev_ids[i].id) {
		case ICE_PEER_RDMA_DEV:
			if (test_bit(ICE_FLAG_IWARP_ENA, pf->flags)) {
				peer_dev->msix_count = pf->num_rdma_msix;
				entry = &pf->msix_entries[pf->rdma_base_vector];
			}
			break;
		default:
			break;
		}

		peer_dev->msix_entries = entry;
		ice_peer_state_change(peer_dev_int, ICE_PEER_DEV_STATE_INIT,
				      false);
		status = platform_device_register(platform_dev);
		if (status) {
			pr_err("Failed to register peer device %s\n",
			       platform_dev->name);
			return status;
		}
	}

	return status;
}

