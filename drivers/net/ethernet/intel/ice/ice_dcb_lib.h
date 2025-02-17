/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019, Intel Corporation. */

#ifndef _ICE_DCB_LIB_H_
#define _ICE_DCB_LIB_H_

#include "ice.h"
#include "ice_lib.h"

#ifdef CONFIG_DCB
#define ICE_TC_MAX_BW 100 /* Default Max BW percentage */

void ice_dcb_rebuild(struct ice_pf *pf);
u8 ice_dcb_get_ena_tc(struct ice_dcbx_cfg *dcbcfg);
u8 ice_dcb_get_num_tc(struct ice_dcbx_cfg *dcbcfg);
void ice_vsi_cfg_dcb_rings(struct ice_vsi *vsi);
int ice_init_pf_dcb(struct ice_pf *pf, bool locked);
void ice_update_dcb_stats(struct ice_pf *pf);
int
ice_tx_prepare_vlan_flags_dcb(struct ice_ring *tx_ring,
			      struct ice_tx_buf *first);
void ice_setup_dcb_qos_info(struct ice_pf *pf, struct ice_qos_params *qos_info);
void
ice_dcb_process_lldp_set_mib_change(struct ice_pf *pf,
				    struct ice_rq_event_info *event);
static inline void
ice_set_cgd_num(struct ice_tlan_ctx *tlan_ctx, struct ice_ring *ring)
{
	tlan_ctx->cgd_num = ring->dcb_tc;
}
#else
#define ice_dcb_rebuild(pf) do {} while (0)

static inline u8 ice_dcb_get_ena_tc(struct ice_dcbx_cfg __always_unused *dcbcfg)
{
	return ICE_DFLT_TRAFFIC_CLASS;
}

static inline u8 ice_dcb_get_num_tc(struct ice_dcbx_cfg __always_unused *dcbcfg)
{
	return 1;
}

static inline int
ice_init_pf_dcb(struct ice_pf *pf, bool __always_unused locked)
{
	dev_dbg(&pf->pdev->dev, "DCB not supported\n");
	return -EOPNOTSUPP;
}

static inline int
ice_tx_prepare_vlan_flags_dcb(struct ice_ring __always_unused *tx_ring,
			      struct ice_tx_buf __always_unused *first)
{
	return 0;
}

#define ice_update_dcb_stats(pf) do {} while (0)
#define ice_vsi_cfg_dcb_rings(vsi) do {} while (0)
#define ice_setup_dcb_qos_info(pf, qos_info) do {} while (0)
#define ice_dcb_process_lldp_set_mib_change(pf, event) do {} while (0)
#define ice_set_cgd_num(tlan_ctx, ring) do {} while (0)
#endif /* CONFIG_DCB */
#endif /* _ICE_DCB_LIB_H_ */
