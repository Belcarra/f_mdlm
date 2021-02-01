// SPDX-License-Identifier: GPL-2.0+
/*
 * f_subset.c -- "CDC Subset" Ethernet link function driver
 *
 * Copyright (C) 2003-2005,2008 David Brownell
 * Copyright (C) 2008 Nokia Corporation
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/crc32.h>

#include "u_ether.h"
#include "u_ether_configfs.h"
#include "u_mdlm.h"

#define BELCARRA_SETIP          0x05
#define BELCARRA_SETMSK         0x06
#define BELCARRA_SETROUTER      0x07


/*
 * This function packages a simple "CDC Subset" Ethernet port with no real
 * control mechanisms; just raw data transfer over two bulk endpoints.
 * The data transfer model is exactly that of CDC Ethernet, which is
 * why we call it the "CDC Subset".
 *
 * Because it's not standardized, this has some interoperability issues.
 * They mostly relate to driver binding, since the data transfer model is
 * so simple (CDC Ethernet).  The original versions of this protocol used
 * specific product/vendor IDs:  byteswapped IDs for Digital Equipment's
 * SA-1100 "Itsy" board, which could run Linux 2.4 kernels and supported
 * daughtercards with USB peripheral connectors.  (It was used more often
 * with other boards, using the Itsy identifiers.)  Linux hosts recognized
 * this with CONFIG_USB_ARMLINUX; these devices have only one configuration
 * and one interface.
 *
 * At some point, MCCI defined a (nonconformant) CDC MDLM variant called
 * "SAFE", which happens to have a mode which is identical to the "CDC
 * Subset" in terms of data transfer and lack of control model.  This was
 * adopted by later Sharp Zaurus models, and by some other software which
 * Linux hosts recognize with CONFIG_USB_NET_ZAURUS.
 *
 * Because Microsoft's RNDIS drivers are far from robust, we added a few
 * descriptors to the CDC Subset code, making this code look like a SAFE
 * implementation.  This lets you use MCCI's host side MS-Windows drivers
 * if you get fed up with RNDIS.  It also makes it easier for composite
 * drivers to work, since they can use class based binding instead of
 * caring about specific product and vendor IDs.
 */

struct f_mdlm {
	struct gether			port;

	char				ethaddr[14];
    bool                crc;
};

static inline struct f_mdlm *func_to_mdlm(struct usb_function *f)
{
	return container_of(f, struct f_mdlm, port.func);
}

/*-------------------------------------------------------------------------*/

/*
 * "Simple" CDC-subset option is a simple vendor-neutral model that most
 * full speed controllers can handle:  one interface, two bulk endpoints.
 * To assist host side drivers, we fancy it up a bit, and add descriptors so
 * some host side drivers will understand it as a "SAFE" variant.
 *
 * "SAFE" loosely follows CDC WMC MDLM, violating the spec in various ways.
 * Data endpoints live in the control interface, there's no data interface.
 * And it's not used to talk to a cell phone radio.
 */

/* interface descriptor: */

static struct usb_interface_descriptor subset_data_intf = {
	.bLength =		sizeof subset_data_intf,
	.bDescriptorType =	USB_DT_INTERFACE,

	/* .bInterfaceNumber = DYNAMIC */
	.bAlternateSetting =	0,
	.bNumEndpoints =	2,
	.bInterfaceClass =      USB_CLASS_COMM,
	.bInterfaceSubClass =	USB_CDC_SUBCLASS_MDLM,
	.bInterfaceProtocol =	0,
	/* .iInterface = DYNAMIC */
};

static struct usb_cdc_header_desc mdlm_header_desc = {
	.bLength =		sizeof mdlm_header_desc,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubType =	USB_CDC_HEADER_TYPE,

	.bcdCDC =		cpu_to_le16(0x0110),
};

__u8 SAFE_bGUID[16] = {
		0x5d, 0x34, 0xcf, 0x66, 0x11, 0x18, 0x11, 0xd6,
		0xa2, 0x1a, 0x00, 0x01, 0x02, 0xca, 0x9a, 0x7f,
};

__u8 BLAN_bGUID[16] = {
        0x74, 0xf0, 0x3d, 0xbd, 0x1e, 0xc1, 0x44, 0x70,  /* bGUID */
        0xa3, 0x67, 0x71, 0x34, 0xc9, 0xf5, 0x54, 0x37,  /* bGUID */
};

static struct usb_cdc_mdlm_desc mdlm_desc = {
	.bLength =		sizeof mdlm_desc,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubType =	USB_CDC_MDLM_TYPE,

	.bcdVersion =		cpu_to_le16(0x0100),
	.bGUID = {
		0x5d, 0x34, 0xcf, 0x66, 0x11, 0x18, 0x11, 0xd6,
		0xa2, 0x1a, 0x00, 0x01, 0x02, 0xca, 0x9a, 0x7f,
	}
    ,
};

static struct usb_cdc_mdlm_desc mdlm_blan_desc = {
	.bLength =		sizeof mdlm_blan_desc,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubType =	USB_CDC_MDLM_TYPE,

	.bcdVersion =		cpu_to_le16(0x0100),
	.bGUID = {
        0x74, 0xf0, 0x3d, 0xbd, 0x1e, 0xc1, 0x44, 0x70,  /* bGUID */
        0xa3, 0x67, 0x71, 0x34, 0xc9, 0xf5, 0x54, 0x37,  /* bGUID */
	},
};


/* since "usb_cdc_mdlm_detail_desc" is a variable length structure, we
 * can't really use its struct.  All we do here is say that we're using
 * the submode of "SAFE" which directly matches the CDC Subset.
 */
static u8 mdlm_detail_desc[] = {
	6,
	USB_DT_CS_INTERFACE,
	USB_CDC_MDLM_DETAIL_TYPE,

	0,	/* "BLAN" */
	0,	/* network control capabilities (none) */
	1,	/* network data capabilities ("raw" encapsulation) */
};

static struct usb_cdc_ether_desc ether_desc = {
	.bLength =		sizeof ether_desc,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubType =	USB_CDC_ETHERNET_TYPE,

	/* this descriptor actually adds value, surprise! */
	/* .iMACAddress = DYNAMIC */
	.bmEthernetStatistics =	cpu_to_le32(0), /* no statistics */
	.wMaxSegmentSize =	cpu_to_le16(ETH_FRAME_LEN),
	.wNumberMCFilters =	cpu_to_le16(0),
	.bNumberPowerFilters =	0,
};

/* full speed support: */

static struct usb_endpoint_descriptor fs_subset_in_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor fs_subset_out_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *fs_eth_function[] = {
	(struct usb_descriptor_header *) &subset_data_intf,
	(struct usb_descriptor_header *) &mdlm_header_desc,
	(struct usb_descriptor_header *) &mdlm_desc,
	(struct usb_descriptor_header *) &mdlm_detail_desc,
	(struct usb_descriptor_header *) &ether_desc,
	(struct usb_descriptor_header *) &fs_subset_in_desc,
	(struct usb_descriptor_header *) &fs_subset_out_desc,
	NULL,
};

/* high speed support: */

static struct usb_endpoint_descriptor hs_subset_in_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_subset_out_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_eth_function[] = {
	(struct usb_descriptor_header *) &subset_data_intf,
	(struct usb_descriptor_header *) &mdlm_header_desc,
	(struct usb_descriptor_header *) &mdlm_desc,
	(struct usb_descriptor_header *) &mdlm_detail_desc,
	(struct usb_descriptor_header *) &ether_desc,
	(struct usb_descriptor_header *) &hs_subset_in_desc,
	(struct usb_descriptor_header *) &hs_subset_out_desc,
	NULL,
};

/* super speed support: */

static struct usb_endpoint_descriptor ss_subset_in_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_endpoint_descriptor ss_subset_out_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_subset_bulk_comp_desc = {
	.bLength =		sizeof ss_subset_bulk_comp_desc,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,

	/* the following 2 values can be tweaked if necessary */
	/* .bMaxBurst =		0, */
	/* .bmAttributes =	0, */
};

static struct usb_descriptor_header *ss_eth_function[] = {
	(struct usb_descriptor_header *) &subset_data_intf,
	(struct usb_descriptor_header *) &mdlm_header_desc,
	(struct usb_descriptor_header *) &mdlm_desc,
	(struct usb_descriptor_header *) &mdlm_detail_desc,
	(struct usb_descriptor_header *) &ether_desc,
	(struct usb_descriptor_header *) &ss_subset_in_desc,
	(struct usb_descriptor_header *) &ss_subset_bulk_comp_desc,
	(struct usb_descriptor_header *) &ss_subset_out_desc,
	(struct usb_descriptor_header *) &ss_subset_bulk_comp_desc,
	NULL,
};

/* string descriptors: */

static struct usb_string mdlm_string_defs[] = {
	[0].s = "CDC Ethernet Subset/SAFE",
	[1].s = "",
	{  } /* end of list */
};

static struct usb_gadget_strings mdlm_string_table = {
	.language =		0x0409,	/* en-us */
	.strings =		mdlm_string_defs,
};

static struct usb_gadget_strings *mdlm_strings[] = {
	&mdlm_string_table,
	NULL,
};

/*-------------------------------------------------------------------------*/

static bool mdlm_crc = true;
static bool mdlm_safe = true;

static ssize_t f_mdlm_crc_show(struct config_item *item, char *page)
{
    return sprintf(page, "%s\n", mdlm_crc ? "y" : "n");
}

static ssize_t f_mdlm_crc_store(struct config_item *item,
                    const char *page, size_t len)
{
    int ret = 0;
    bool val = 0;
    ret = kstrtobool(page, &val);
    if (ret)
        goto end;
    mdlm_crc = val;
    ret = len;
end:
    return len;
}

CONFIGFS_ATTR(f_mdlm_, crc);

static ssize_t f_mdlm_mdlm_show(struct config_item *item, char *page)
{
    return sprintf(page, "%s\n", mdlm_safe ? "SAFE" : "BLAN");
}

static ssize_t f_mdlm_mdlm_store(struct config_item *item,
                    const char *page, size_t len)
{
    int ret = 0;
    if (strncmp(page, "SAFE", 4) == 0) {
        mdlm_safe = true;
    }
    else if (strncmp(page, "BLAN", 4) == 0) {
        mdlm_safe = false;
    }
    else {
        goto end;
    }
    ret = len;
end:
    return len;
}
CONFIGFS_ATTR(f_mdlm_, mdlm);


static int mdlm_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct f_mdlm		*geth = func_to_mdlm(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct net_device	*net;

	/* we know alt == 0, so this is an activation or a reset */

	if (geth->port.in_ep->enabled) {
		DBG(cdev, "reset cdc subset\n");
		gether_disconnect(&geth->port);
	}

	DBG(cdev, "init + activate cdc subset\n");
	if (config_ep_by_speed(cdev->gadget, f, geth->port.in_ep) ||
	    config_ep_by_speed(cdev->gadget, f, geth->port.out_ep)) {
		geth->port.in_ep->desc = NULL;
		geth->port.out_ep->desc = NULL;
		return -EINVAL;
	}

	net = gether_connect(&geth->port);
	return PTR_ERR_OR_ZERO(net);
}

static void mdlm_disable(struct usb_function *f)
{
	struct f_mdlm	*geth = func_to_mdlm(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	DBG(cdev, "net deactivated\n");
	gether_disconnect(&geth->port);
}

/*-------------------------------------------------------------------------*/


static int mdlm_setup(struct usb_function *f, const struct usb_ctrlrequest *ctrl)
{
    //struct f_mdlm        *geth = func_to_mdlm(f);
    struct usb_composite_dev *cdev = f->config->cdev;
    struct usb_request  *req = cdev->req;
    int         value = -EOPNOTSUPP;
    u16         w_index = le16_to_cpu(ctrl->wIndex);
    u16         w_value = le16_to_cpu(ctrl->wValue);
    u16         w_length = le16_to_cpu(ctrl->wLength);

    INFO(cdev, "mdlm_setup: bRequestType: %02x bRequest: %02x wValue: %04x wIndex: %04x", 
            ctrl->bRequestType, ctrl->bRequest, ctrl->wValue, ctrl->wIndex );

    if (mdlm_safe)
        goto invalid;

    switch ((ctrl->bRequestType << 8) | ctrl->bRequest) {
    case ((USB_TYPE_VENDOR << 8) | BELCARRA_SETIP):
    case ((USB_TYPE_VENDOR << 8) | BELCARRA_SETMSK):
    case ((USB_TYPE_VENDOR << 8) | BELCARRA_SETROUTER):
        value = 0;
        break;
    default:
        goto invalid;
    }

invalid:

    /* respond with data transfer or status phase? */
    if (value >= 0) {
        DBG(cdev, "mdlm req%02x.%02x v%04x i%04x l%d\n",
            ctrl->bRequestType, ctrl->bRequest,
            w_value, w_index, w_length);
        req->zero = 0;
        req->length = value;
        value = usb_ep_queue(cdev->gadget->ep0, req, GFP_ATOMIC);
        if (value < 0)
            ERROR(cdev, "mdlm req %02x.%02x response err %d\n",
                    ctrl->bRequestType, ctrl->bRequest,
                    value);
    }

    /* device either stalls (value < 0) or reports success */
    return value;
}




/* serial function driver setup/binding */

static int
mdlm_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_mdlm		*geth = func_to_mdlm(f);
	struct usb_string	*us;
	int			status;
	struct usb_ep		*ep;


	struct f_mdlm_opts	*mdlm_opts;

    INFO(cdev, "mdlm_bind: mdlm_crc: %d mdlm_safe: %d", mdlm_crc, mdlm_safe);

    memcpy(mdlm_desc.bGUID, mdlm_safe ? SAFE_bGUID : BLAN_bGUID, sizeof (mdlm_desc.bGUID));
    if (mdlm_crc) {

    }
    else {
        mdlm_detail_desc[5] &= 0xfe;
    }
    
	mdlm_opts = container_of(f->fi, struct f_mdlm_opts, func_inst);

	/*
	 * in drivers/usb/gadget/configfs.c:configfs_composite_bind()
	 * configurations are bound in sequence with list_for_each_entry,
	 * in each configuration its functions are bound in sequence
	 * with list_for_each_entry, so we assume no race condition
	 * with regard to mdlm_opts->bound access
	 */
	if (!mdlm_opts->bound) {
		mutex_lock(&mdlm_opts->lock);
		gether_set_gadget(mdlm_opts->net, cdev->gadget);
		status = gether_register_netdev(mdlm_opts->net);
		mutex_unlock(&mdlm_opts->lock);
		if (status)
			return status;
		mdlm_opts->bound = true;
	}

	us = usb_gstrings_attach(cdev, mdlm_strings,
				 ARRAY_SIZE(mdlm_string_defs));
	if (IS_ERR(us))
		return PTR_ERR(us);

	subset_data_intf.iInterface = us[0].id;
	ether_desc.iMACAddress = us[1].id;

	/* allocate instance-specific interface IDs */
	status = usb_interface_id(c, f);
	if (status < 0)
		goto fail;
	subset_data_intf.bInterfaceNumber = status;

	status = -ENODEV;

	/* allocate instance-specific endpoints */
	ep = usb_ep_autoconfig(cdev->gadget, &fs_subset_in_desc);
	if (!ep)
		goto fail;
	geth->port.in_ep = ep;

	ep = usb_ep_autoconfig(cdev->gadget, &fs_subset_out_desc);
	if (!ep)
		goto fail;
	geth->port.out_ep = ep;

	/* support all relevant hardware speeds... we expect that when
	 * hardware is dual speed, all bulk-capable endpoints work at
	 * both speeds
	 */
	hs_subset_in_desc.bEndpointAddress = fs_subset_in_desc.bEndpointAddress;
	hs_subset_out_desc.bEndpointAddress =
		fs_subset_out_desc.bEndpointAddress;

	ss_subset_in_desc.bEndpointAddress = fs_subset_in_desc.bEndpointAddress;
	ss_subset_out_desc.bEndpointAddress =
		fs_subset_out_desc.bEndpointAddress;



	status = usb_assign_descriptors(f, fs_eth_function, hs_eth_function,
			ss_eth_function, NULL);
	if (status)
		goto fail;

	/* NOTE:  all that is done without knowing or caring about
	 * the network link ... which is unavailable to this code
	 * until we're activated via set_alt().
	 */

	INFO(cdev, "CDC Subset/BLAN: %s speed IN/%s OUT/%s\n",
			gadget_is_superspeed(c->cdev->gadget) ? "super" :
			gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
			geth->port.in_ep->name, geth->port.out_ep->name);
	return 0;

fail:
	ERROR(cdev, "%s: can't bind, err %d\n", f->name, status);

	return status;
}

static inline struct f_mdlm_opts *to_f_mdlm_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_mdlm_opts,
			    func_inst.group);
}

/* f_mdlm_item_ops */
USB_ETHERNET_CONFIGFS_ITEM(mdlm);

/* f_mdlm_opts_dev_addr */
USB_ETHERNET_CONFIGFS_ITEM_ATTR_DEV_ADDR(mdlm);

/* f_mdlm_opts_host_addr */
USB_ETHERNET_CONFIGFS_ITEM_ATTR_HOST_ADDR(mdlm);

/* f_mdlm_opts_qmult */
USB_ETHERNET_CONFIGFS_ITEM_ATTR_QMULT(mdlm);

/* f_mdlm_opts_ifname */
USB_ETHERNET_CONFIGFS_ITEM_ATTR_IFNAME(mdlm);

static struct configfs_attribute *mdlm_attrs[] = {
	&mdlm_opts_attr_dev_addr,
	&mdlm_opts_attr_host_addr,
	&mdlm_opts_attr_qmult,
	&mdlm_opts_attr_ifname,
    &f_mdlm_attr_crc,
    &f_mdlm_attr_mdlm,
	NULL,
};

static const struct config_item_type mdlm_func_type = {
	.ct_item_ops	= &mdlm_item_ops,
	.ct_attrs	= mdlm_attrs,
	.ct_owner	= THIS_MODULE,
};

/*
 */
static struct sk_buff *mdlm_wrap(struct gether *port, struct sk_buff *skb)
{
    struct sk_buff  *skb2 = NULL;
    struct usb_ep   *in = port->in_ep;
    int     headroom, tailroom, padlen = 0;
    u16     len;
    uint32_t crc;
    __le16 *crc_pos;

    if (!skb)
        return NULL;

    if (!mdlm_crc)
        return skb;

    len = skb->len;
    headroom = skb_headroom(skb);
    tailroom = skb_tailroom(skb);

    /* When (len + EEM_HLEN + ETH_FCS_LEN) % in->maxpacket) is 0,
     * stick two bytes of zero-length EEM packet on the end.
     */
    if (((len + 5) % in->maxpacket) == 0)
        padlen += 2;

    if (tailroom >= 5)
        goto done;

    skb2 = skb_copy_expand(skb, 0,ETH_FCS_LEN + padlen , GFP_ATOMIC);
    dev_kfree_skb_any(skb);
    skb = skb2;
    if (!skb)
        return skb;

done:

    crc = ~crc32_le(~0, skb->data, skb->len);
    crc_pos = skb_put(skb, sizeof(uint32_t));
    put_unaligned_le32(crc, crc_pos);
    
    /* use the "no CRC" option */
    //put_unaligned_be32(0xdeadbeef, skb_put(skb, 4));
    return skb;
}


static void mdlm_free_inst(struct usb_function_instance *f)
{
	struct f_mdlm_opts *opts;

	opts = container_of(f, struct f_mdlm_opts, func_inst);
	if (opts->bound)
		gether_cleanup(netdev_priv(opts->net));
	else
		free_netdev(opts->net);
	kfree(opts);
}

static struct usb_function_instance *mdlm_alloc_inst(void)
{
	struct f_mdlm_opts *opts;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return ERR_PTR(-ENOMEM);
	mutex_init(&opts->lock);
	opts->func_inst.free_func_inst = mdlm_free_inst;
	opts->net = gether_setup_default();
	if (IS_ERR(opts->net)) {
		struct net_device *net = opts->net;
		kfree(opts);
		return ERR_CAST(net);
	}

	config_group_init_type_name(&opts->func_inst.group, "",
				    &mdlm_func_type);

	return &opts->func_inst;
}

static void mdlm_free(struct usb_function *f)
{
	struct f_mdlm *eth;
	eth = func_to_mdlm(f);
	kfree(eth);
}

static void mdlm_unbind(struct usb_configuration *c, struct usb_function *f)
{
	mdlm_string_defs[0].id = 0;
	usb_free_all_descriptors(f);
}

static struct usb_function *mdlm_alloc(struct usb_function_instance *fi)
{
	struct f_mdlm	*geth;
	struct f_mdlm_opts *opts;
	int status;

	/* allocate and initialize one new instance */
	geth = kzalloc(sizeof(*geth), GFP_KERNEL);
	if (!geth)
		return ERR_PTR(-ENOMEM);

	opts = container_of(fi, struct f_mdlm_opts, func_inst);

	mutex_lock(&opts->lock);
	opts->refcnt++;
	/* export host's Ethernet address in CDC format */
	status = gether_get_host_addr_cdc(opts->net, geth->ethaddr,
					  sizeof(geth->ethaddr));
	if (status < 12) {
		kfree(geth);
		mutex_unlock(&opts->lock);
		return ERR_PTR(-EINVAL);
	}
	mdlm_string_defs[1].s = geth->ethaddr;

	geth->port.ioport = netdev_priv(opts->net);
	mutex_unlock(&opts->lock);
	geth->port.cdc_filter = DEFAULT_FILTER;

	geth->port.func.name = "cdc_mdlm";
	geth->port.func.bind = mdlm_bind;
	geth->port.func.unbind = mdlm_unbind;
	geth->port.func.set_alt = mdlm_set_alt;
	geth->port.func.setup = mdlm_setup;
	geth->port.func.disable = mdlm_disable;
	geth->port.func.free_func = mdlm_free;
	geth->port.wrap = mdlm_wrap;

	return &geth->port.func;
}

DECLARE_USB_FUNCTION_INIT(mdlm, mdlm_alloc_inst, mdlm_alloc);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Brownell");
