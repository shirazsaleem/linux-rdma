/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018, Intel Corporation. */

#ifndef _ICE_IDC_INT_H_
#define _ICE_IDC_INT_H_

#include "ice_idc.h"

#define ICE_IDC_MAX_STATE_WAIT	12
extern struct list_head ice_peer_drv_list;
extern struct mutex ice_peer_drv_mutex; /* control access to list of peer_drv */
int ice_prep_peer_for_reset(struct device *dev, void *data);
int ice_close_peer_for_reset(struct device *dev, void *data);
int ice_unroll_peer(struct device *dev, void *data);
int ice_unreg_peer_device(struct device *dev, void *data);
int ice_peer_close(struct device *dev, void *data);
int ice_peer_check_for_reg(struct device *dev, void *data);
int ice_finish_init_peer_device(struct device *dev, void *data);

enum ice_peer_dev_state {
	ICE_PEER_DEV_STATE_INIT,
	ICE_PEER_DEV_STATE_PROBE,
	ICE_PEER_DEV_STATE_PROBED,
	ICE_PEER_DEV_STATE_OPENING,
	ICE_PEER_DEV_STATE_OPENED,
	ICE_PEER_DEV_STATE_PREP_RST,
	ICE_PEER_DEV_STATE_PREPPED,
	ICE_PEER_DEV_STATE_CLOSING,
	ICE_PEER_DEV_STATE_CLOSED,
	ICE_PEER_DEV_STATE_REMOVED,
	ICE_PEER_DEV_STATE_API_RDY,
	ICE_PEER_DEV_STATE_NBITS,               /* must be last */
};

enum ice_peer_drv_state {
	ICE_PEER_DRV_STATE_MBX_RDY,
	ICE_PEER_DRV_STATE_NBITS,               /* must be last */
};

struct ice_peer_dev_int {
	struct ice_peer_dev peer_dev; /* public structure */

	/* if this peer_dev is the originator of an event, these are the
	 * most recent events of each type
	 */
	struct ice_event current_events[ICE_EVENT_NBITS];
	/* Events a peer has registered to be notified about */
	DECLARE_BITMAP(events, ICE_EVENT_NBITS);

	/* States associated with peer device */
	DECLARE_BITMAP(state, ICE_PEER_DEV_STATE_NBITS);
	struct mutex peer_dev_state_mutex; /* peer_dev state mutex */

	/* per peer workqueue */
	struct workqueue_struct *ice_peer_wq;

	struct work_struct peer_prep_task;
	struct work_struct peer_close_task;

	enum ice_close_reason rst_type;
};

struct ice_peer_drv_int {
	struct ice_peer_drv *peer_drv;

	/* list of peer_drv_int */
	struct list_head drv_int_list;

	/* States associated with peer driver */
	DECLARE_BITMAP(state, ICE_PEER_DRV_STATE_NBITS);

	/* if this peer_dev is the originator of an event, these are the
	 * most recent events of each type
	 */
	struct ice_event current_events[ICE_EVENT_NBITS];
};

static inline
struct ice_peer_dev_int *peer_to_ice_dev_int(struct ice_peer_dev *peer_dev)
{
	return container_of(peer_dev, struct ice_peer_dev_int, peer_dev);
}

static inline
struct ice_peer_drv_int *peer_to_ice_drv_int(struct ice_peer_drv *peer_drv)
{
	struct ice_peer_drv_int *drv_int;

	mutex_lock(&ice_peer_drv_mutex);
	list_for_each_entry(drv_int, &ice_peer_drv_list, drv_int_list) {
		if (drv_int->peer_drv == peer_drv) {
			mutex_unlock(&ice_peer_drv_mutex);
			return drv_int;
		}
	}

	mutex_unlock(&ice_peer_drv_mutex);

	return NULL;
}

#endif /* !_ICE_IDC_INT_H_ */
