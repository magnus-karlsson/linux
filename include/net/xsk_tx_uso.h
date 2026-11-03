/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XSK_TX_USO_H
#define _NET_XSK_TX_USO_H

#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <net/udp.h>
#include <net/xsk_buff_pool.h>

#define XSK_TX_USO_MAX_HEADER 256

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

struct xsk_tx_uso {
	struct xsk_tx_uso_info info;
	u8 buffer[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
};

static inline void *xsk_tx_uso_header(struct xsk_tx_uso *uso)
{
	return uso->buffer + NET_IP_ALIGN;
}

/**
 * xsk_tx_prepare_gso_headers - prepare IP and transport headers for segmentation
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
	struct iphdr *iph;

	if (outer_ip_header) {
		iph = outer_ip_header;
		if (iph->version == 4) {
			iph->tot_len = 0;
			iph->check = 0;
		} else {
			struct ipv6hdr *ip6h = outer_ip_header;

			ip6h->payload_len = 0;
		}
	}

	if (outer_udp) {
		udp_set_len_short(outer_udp, 0);
		csum_replace_by_diff(&outer_udp->check,
				     (__force __wsum)htonl(outer_udp_len));
	}

	iph = ip_header;
	if (iph->version == 4) {
		iph->tot_len = 0;
		iph->check = 0;
	} else {
		struct ipv6hdr *ip6h = ip_header;

		ip6h->payload_len = 0;
	}

	csum_replace_by_diff(transport_checksum,
			     (__force __wsum)htonl(transport_len));
}

#ifdef CONFIG_XDP_SOCKETS
int xsk_tx_uso_validate(const void *header, struct xsk_tx_uso_info *uso, u32 mtu);
struct xsk_tx_uso *xsk_tx_uso_parse(struct xsk_buff_pool *pool, const struct xdp_desc *descs,
				    u32 nr, struct xsk_tx_uso *uso);
void xsk_tx_uso_prepare_headers(struct xsk_tx_uso *uso);

#else

static inline int
xsk_tx_uso_validate(const void *header, struct xsk_tx_uso_info *uso, u32 mtu)
{
	return -EOPNOTSUPP;
}

static inline struct xsk_tx_uso *
xsk_tx_uso_parse(struct xsk_buff_pool *pool, const struct xdp_desc *descs,
		 u32 nr, struct xsk_tx_uso *uso)
{
	return NULL;
}

static inline void xsk_tx_uso_prepare_headers(struct xsk_tx_uso *uso)
{
}
#endif

#endif
