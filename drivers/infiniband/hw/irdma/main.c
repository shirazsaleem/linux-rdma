// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2019, Intel Corporation. */

#include "main.h"

#ifndef CONFIG_DYNAMIC_DEBUG
static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "debug flags: 0=disabled (default), 0x7fffffff=all");
#endif

static int resource_profile;
module_param(resource_profile, int, 0644);
MODULE_PARM_DESC(resource_profile, "Resource Profile: 0=PF only, 1=Weighted VF, 2=Even Distribution");

static int max_rdma_vfs = 32;
module_param(max_rdma_vfs, int, 0644);
MODULE_PARM_DESC(max_rdma_vfs, "Maximum VF count: 0-32 32=default");

static int roce_ena;
module_param(roce_ena, int, 0644);
MODULE_PARM_DESC(roce_ena, "RoCE enable bitmap: 1=port0,2=port1....0=disabled, not supported on X722");

static int limits_sel;
module_param(limits_sel, int, 0644);
MODULE_PARM_DESC(limits_sel, "Resource limits selector, Range: 0-3");

MODULE_AUTHOR("Intel Corporation, <e1000-rdma@lists.sourceforge.net>");
MODULE_DESCRIPTION("Intel(R) Ethernet Connection RDMA Driver");
MODULE_LICENSE("Dual BSD/GPL");
/* Add an alias for i40iw once its deprecated from kernel.
 * If required add push_mode and mpa_version as deprecated
 * module params for i40iw compat.
 */

LIST_HEAD(irdma_handlers);
DEFINE_SPINLOCK(irdma_handler_lock);

static struct notifier_block irdma_inetaddr_notifier = {
	.notifier_call = irdma_inetaddr_event
};

static struct notifier_block irdma_inetaddr6_notifier = {
	.notifier_call = irdma_inet6addr_event
};

static struct notifier_block irdma_net_notifier = {
	.notifier_call = irdma_net_event
};

static struct notifier_block irdma_netdevice_notifier = {
	.notifier_call = irdma_netdevice_event
};

void irdma_init_rf_params(struct irdma_pci_f *rf)
{
	rf->limits_sel = limits_sel;
	if (rf->rdma_ver != IRDMA_GEN_1)
		rf->roce_ena = roce_ena;
	rf->rsrc_profile = (resource_profile < IRDMA_HMC_PROFILE_EQUAL) ?
			    (u8)resource_profile + IRDMA_HMC_PROFILE_DEFAULT :
			    IRDMA_HMC_PROFILE_DEFAULT;
	rf->max_rdma_vfs = (rf->rsrc_profile != IRDMA_HMC_PROFILE_DEFAULT) ?
			    max_rdma_vfs : 0;
	rf->max_ena_vfs = rf->max_rdma_vfs;
#ifndef CONFIG_DYNAMIC_DEBUG
	rf->debug = debug;
#endif
}

/**
 * irdma_get_device - find a iwdev given a netdev
 * @netdev: pointer to net_device
 *
 * This function takes a reference on ibdev and prevents ib
 * device deregistration. The caller must call a matching
 * irdma_put_device.
 */
struct irdma_device *irdma_get_device(struct net_device *netdev)
{
	struct ib_device *ibdev = ib_device_get_by_netdev(netdev,
							  RDMA_DRIVER_I40IW);

	if (!ibdev)
		return NULL;

	return to_iwdev(ibdev);
}

/**
 * irdma_put_device - release ibdev refcnt
 * @iwdev: device
 *
 * release refcnt on ibdev taken with irdma_get_device.
 */
void irdma_put_device(struct irdma_device *iwdev)
{
	struct ib_device *ibdev = &iwdev->iwibdev->ibdev;

	ib_device_put(ibdev);
}

/**
 * irdma_find_ice_handler - find a handler given a client info
 * @pdev: pointer to pci dev info
 */
struct irdma_handler *irdma_find_handler(struct pci_dev *pdev)
{
	struct irdma_handler *hdl;
	unsigned long flags;

	spin_lock_irqsave(&irdma_handler_lock, flags);
	list_for_each_entry (hdl, &irdma_handlers, list) {
		if (hdl->rf.pdev->devfn == pdev->devfn &&
		    hdl->rf.pdev->bus->number == pdev->bus->number) {
			spin_unlock_irqrestore(&irdma_handler_lock, flags);
			return hdl;
		}
	}
	spin_unlock_irqrestore(&irdma_handler_lock, flags);

	return NULL;
}

/**
 * irdma_add_handler - add a handler to the list
 * @hdl: handler to be added to the handler list
 */
void irdma_add_handler(struct irdma_handler *hdl)
{
	unsigned long flags;

	spin_lock_irqsave(&irdma_handler_lock, flags);
	list_add(&hdl->list, &irdma_handlers);
	spin_unlock_irqrestore(&irdma_handler_lock, flags);
}

/**
 * irdma_del_handler - delete a handler from the list
 * @hdl: handler to be deleted from the handler list
 */
void irdma_del_handler(struct irdma_handler *hdl)
{
	unsigned long flags;

	spin_lock_irqsave(&irdma_handler_lock, flags);
	list_del(&hdl->list);
	spin_unlock_irqrestore(&irdma_handler_lock, flags);
}

/**
 * irdma_register_notifiers - register tcp ip notifiers
 */
void irdma_register_notifiers(void)
{
	register_inetaddr_notifier(&irdma_inetaddr_notifier);
	register_inet6addr_notifier(&irdma_inetaddr6_notifier);
	register_netevent_notifier(&irdma_net_notifier);
	register_netdevice_notifier(&irdma_netdevice_notifier);
}

void irdma_unregister_notifiers(void)
{
	unregister_netevent_notifier(&irdma_net_notifier);
	unregister_inetaddr_notifier(&irdma_inetaddr_notifier);
	unregister_inet6addr_notifier(&irdma_inetaddr6_notifier);
	unregister_netdevice_notifier(&irdma_netdevice_notifier);
}

/**
 * irdma_add_ipv6_addr - add ipv6 address to the hw arp table
 * @iwdev: iwarp device
 */
static void irdma_add_ipv6_addr(struct irdma_device *iwdev)
{
	struct net_device *ip_dev;
	struct inet6_dev *idev;
	struct inet6_ifaddr *ifp, *tmp;
	u32 local_ipaddr6[4];

	rcu_read_lock();
	for_each_netdev_rcu (&init_net, ip_dev) {
		if (((rdma_vlan_dev_vlan_id(ip_dev) < 0xFFFF &&
		      rdma_vlan_dev_real_dev(ip_dev) == iwdev->netdev) ||
		      ip_dev == iwdev->netdev) && ip_dev->flags & IFF_UP) {
			idev = __in6_dev_get(ip_dev);
			if (!idev) {
				dev_err(to_device(&iwdev->rf->sc_dev),
					"ipv6 inet device not found\n");
				break;
			}
			list_for_each_entry_safe (ifp, tmp, &idev->addr_list,
						  if_list) {
				dev_info(to_device(&iwdev->rf->sc_dev),
					 "IP=%pI6, vlan_id=%d, MAC=%pM\n",
					 &ifp->addr,
					 rdma_vlan_dev_vlan_id(ip_dev),
					 ip_dev->dev_addr);

				irdma_copy_ip_ntohl(local_ipaddr6,
						    ifp->addr.in6_u.u6_addr32);
				irdma_manage_arp_cache(iwdev->rf,
						       ip_dev->dev_addr,
						       local_ipaddr6, false,
						       IRDMA_ARP_ADD);
			}
		}
	}
	rcu_read_unlock();
}

/**
 * irdma_add_ipv4_addr - add ipv4 address to the hw arp table
 * @iwdev: iwarp device
 */
static void irdma_add_ipv4_addr(struct irdma_device *iwdev)
{
	struct net_device *dev;
	struct in_device *idev;
	bool got_lock = true;
	u32 ip_addr;

	if (!rtnl_trylock())
		got_lock = false;

	for_each_netdev (&init_net, dev) {
		if (((rdma_vlan_dev_vlan_id(dev) < 0xFFFF &&
		      rdma_vlan_dev_real_dev(dev) == iwdev->netdev) ||
		      dev == iwdev->netdev) && dev->flags & IFF_UP) {
			idev = in_dev_get(dev);
			for_ifa(idev)
			{
				irdma_debug(&iwdev->rf->sc_dev, IRDMA_DEBUG_CM,
					    "IP=%pI4, vlan_id=%d, MAC=%pM\n",
					    &ifa->ifa_address,
					    rdma_vlan_dev_vlan_id(dev),
					    dev->dev_addr);

				ip_addr = ntohl(ifa->ifa_address);
				irdma_manage_arp_cache(iwdev->rf, dev->dev_addr,
						       &ip_addr, true,
						       IRDMA_ARP_ADD);
			}
			endfor_ifa(idev);
			in_dev_put(idev);
		}
	}
	if (got_lock)
		rtnl_unlock();
}

/**
 * irdma_add_ip - add ip addresses
 * @iwdev: iwarp device
 *
 * Add ipv4/ipv6 addresses to the arp cache
 */
void irdma_add_ip(struct irdma_device *iwdev)
{
	irdma_add_ipv4_addr(iwdev);
	irdma_add_ipv6_addr(iwdev);
}

/**
 * irdma_request_reset - Request a reset
 * @rf: RDMA PCI function
 *
 */
void irdma_request_reset(struct irdma_pci_f *rf)
{
	dev_warn(to_device(&rf->sc_dev),
		 "Requesting a a reset from LAN driver\n");
	if (rf->rdma_ver == IRDMA_GEN_1)
		i40iw_request_reset(rf);
	else
		icrdma_request_reset(rf);
}

static int irdma_bus_probe(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	u8 peer_type = id->driver_data;
	int ret = -ENODEV;

	switch (peer_type) {
	case ICE_PEER_DEV:
		ret = irdma_probe(pdev);
		break;
	case I40E_PEER_DEV:
		/* TODO: Add i40e dev support */
	default:
		break;
	}

	return ret;
}

static int irdma_bus_remove(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	u8 peer_type = id->driver_data;

	switch (peer_type) {
	case ICE_PEER_DEV:
		irdma_remove(pdev);
		break;
	case I40E_PEER_DEV:
		/* TODO: Add i40e dev support */
	default:
		break;
	}

	return 0;
}

static const struct platform_device_id irdma_platform_id_table[] = {
	{"rdma_ice", ICE_PEER_DEV},
	/* TODO: Add i40e dev support
	 * Add this entry to the table.
	 * {"rdma_i40e", I40E_PEER_DEV}
	 */
	{},
};

MODULE_DEVICE_TABLE(platform, irdma_platform_id_table);

struct platform_driver irdma_pdriver = {
	.probe = irdma_bus_probe,
	.remove = irdma_bus_remove,
	.id_table = irdma_platform_id_table,
	.driver = {
		   .name = "irdma",
		   .owner = THIS_MODULE,
		  },
};

/**
 * irdma_init_module - driver initialization function
 *
 * First function to call when the driver is loaded
 * Register the driver as ice client and port mapper client
 */
static int __init irdma_init_module(void)
{
	int ret;

	ret = platform_driver_register(&irdma_pdriver);
	if (ret) {
		pr_err("Failed irdma platform_driver_register()\n");
		return ret;
	}
	irdma_register_notifiers();

	return 0;
}

/**
 * irdma_exit_module - driver exit clean up function
 *
 * The function is called just before the driver is unloaded
 * Unregister the driver as ice client and port mapper client
 */
static void __exit irdma_exit_module(void)
{
	irdma_unregister_notifiers();
	platform_driver_unregister(&irdma_pdriver);
}

module_init(irdma_init_module);
module_exit(irdma_exit_module);
