// SPDX-License-Identifier: GPL-2.0
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <net/xsk_tx_uso.h>

/**
 * xsk_tx_uso_validate - validate a kernel-owned plain UDP header
 * @header: kernel-owned buffer containing at least uso->header_len bytes
 * @uso: packet length and metadata offsets; receives protocol and segment count
 * @mtu: maximum output IP packet length
 *
 * The link-layer header is not parsed. The IP header starts at network_offset
 * and its version selects IPv4 or IPv6. The caller must provide a nonzero
 * gso_size other than GSO_BY_FRAGS and header_len equal to transport_offset
 * plus the UDP header size.
 *
 * Return: zero on success or a negative error code.
 */
int xsk_tx_uso_validate(const void *header, struct xsk_tx_uso_info *uso,
			u32 mtu)
{
	const struct xsk_tx_metadata *meta = &uso->metadata;
	u32 nhoff = meta->request.network_offset;
	u32 thoff = meta->request.csum_start;
	u32 udp_len, payload_len, network_len;
	const struct udphdr *uh;
	__be16 protocol;

	if (nhoff < ETH_HLEN || thoff <= nhoff || uso->header_len < thoff ||
	    uso->len < uso->header_len)
		return -EINVAL;

	network_len = uso->len - nhoff;
	switch (*(const u8 *)(header + nhoff) >> 4) {
	case 4: {
		const struct iphdr *iph = header + nhoff;

		if (thoff - nhoff < sizeof(*iph) ||
		    iph->ihl < 5 || iph->ihl * 4 != thoff - nhoff ||
		    ip_is_fragment(iph) ||
		    ntohs(iph->tot_len) != network_len)
			return -EINVAL;
		protocol = htons(ETH_P_IP);
		uso->l4_protocol = iph->protocol;
		break;
	}
	case 6: {
		const struct ipv6hdr *ip6h = header + nhoff;

		if (thoff - nhoff != sizeof(*ip6h) ||
		    ntohs(ip6h->payload_len) != network_len - sizeof(*ip6h))
			return -EINVAL;
		protocol = htons(ETH_P_IPV6);
		uso->l4_protocol = ip6h->nexthdr;
		break;
	}
	default:
		return -EPROTONOSUPPORT;
	}
	uso->protocol = protocol;
	udp_len = uso->len - thoff;
	uh = header + thoff;
	if (uso->l4_protocol != IPPROTO_UDP || udp_len > U16_MAX ||
	    ntohs(uh->len) != udp_len)
		return -EINVAL;
	payload_len = udp_len - sizeof(*uh);
	if (payload_len > meta->request.gso_size * UDP_MAX_SEGMENTS ||
	    uso->header_len - nhoff +
	    min_t(u32, payload_len, meta->request.gso_size) > mtu)
		return -EINVAL;

	uso->l4_len = sizeof(*uh);
	uso->gso_segs = max_t(u32, 1, DIV_ROUND_UP(payload_len,
						   meta->request.gso_size));
	return 0;
}
EXPORT_SYMBOL_GPL(xsk_tx_uso_validate);
