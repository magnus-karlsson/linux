/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XSK_TX_USO_H
#define _NET_XSK_TX_USO_H

#include <linux/errno.h>
#include <linux/types.h>
#include <net/xsk_buff_pool.h>

/*
 * Header offsets are relative to the start of the supplied Ethernet frame.
 * The caller provides header_len stable, linear bytes and the full packet len.
 */
struct xsk_tx_uso_info {
	struct xsk_tx_metadata metadata;
	u32 len;
	u16 header_len;
	u16 gso_segs;
	__be16 protocol;
	u8 l4_protocol;
	u8 l4_len;
};

#ifdef CONFIG_XDP_SOCKETS
int xsk_tx_uso_validate(const void *header, struct xsk_tx_uso_info *uso,
			u32 mtu);
#else
static inline int
xsk_tx_uso_validate(const void *header, struct xsk_tx_uso_info *uso, u32 mtu)
{
	return -EOPNOTSUPP;
}
#endif

#endif
