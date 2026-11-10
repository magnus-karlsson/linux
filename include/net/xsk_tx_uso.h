/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XSK_TX_USO_H
#define _NET_XSK_TX_USO_H

#include <linux/errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <net/checksum.h>
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

static inline void xsk_tx_clear_ip_len(void *ip_header)
{
	struct iphdr *iph = ip_header;

	if (iph->version == 4) {
		iph->tot_len = 0;
		iph->check = 0;
	} else {
		struct ipv6hdr *ip6h = ip_header;

		ip6h->payload_len = 0;
	}
}

/**
 * xsk_tx_prepare_gso_headers - prepare IP and L4 headers for segmentation
 * @outer_ip_header: optional outer IP header
 * @outer_udp: optional outer UDP header to prepare
 * @outer_udp_len: aggregate outer UDP length
 * @ip_header: IP header at the start of the network header
 * @transport_checksum: transport checksum field
 * @transport_len: transport header and aggregate payload length
 *
 * Clear IP length/checksum fields and remove aggregate transport lengths from
 * partial checksum seeds before hardware segmentation. If @outer_udp is set,
 * its length is cleared and @outer_udp_len is removed from its checksum seed.
 */
static inline void
xsk_tx_prepare_gso_headers(void *outer_ip_header, struct udphdr *outer_udp,
			   u32 outer_udp_len, void *ip_header,
			   __sum16 *transport_checksum, u32 transport_len)
{
	if (outer_ip_header)
		xsk_tx_clear_ip_len(outer_ip_header);

	if (outer_udp) {
		udp_set_len_short(outer_udp, 0);
		csum_replace_by_diff(&outer_udp->check,
				     (__force __wsum)htonl(outer_udp_len));
	}

	xsk_tx_clear_ip_len(ip_header);

	csum_replace_by_diff(transport_checksum,
			     (__force __wsum)htonl(transport_len));
}

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
