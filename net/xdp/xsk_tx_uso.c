// SPDX-License-Identifier: GPL-2.0
#include <net/gso.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <net/xdp_sock_drv.h>
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

/**
 * xsk_tx_uso_parse - snapshot and validate an AF_XDP USO packet
 * @pool: pool owning the validated descriptors
 * @descs: kernel-owned descriptors, starting at the beginning of a packet
 * @nr: nonzero number of descriptors, including the final EOP descriptor
 * @info: receives the snapshotted metadata and the parsed header layout
 * @header: storage for at least XSK_TX_USO_MAX_HEADER bytes of packet header
 *
 * Metadata is snapshotted before using its offsets. The packet header is
 * copied exactly once, before any parsing. @header must remain valid until
 * DMA completes if this packet is transmitted.
 *
 * Return: 1 for a valid USO request, 0 without USO, or a negative error code.
 */
int xsk_tx_uso_parse(struct xsk_buff_pool *pool, const struct xdp_desc *descs,
		     u32 nr, struct xsk_tx_uso_info *info, void *header)
{
	struct xsk_tx_metadata *meta = &info->metadata;
	struct xsk_tx_metadata *user_meta;
	u32 header_len, len = 0, i;
	u64 flags;
	int err;

	user_meta = xsk_buff_get_metadata(pool, descs->addr, descs->options);
	if (!user_meta)
		return 0;
	memcpy(meta, user_meta,
	       min_t(size_t, pool->tx_metadata_len, sizeof(*meta)));
	if (!(meta->flags & XDP_TXMD_FLAGS_USO))
		return 0;
	if (!xsk_buff_valid_tx_metadata(pool, meta, &flags) ||
	    !xsk_tx_uso_flags_valid(flags) ||
	    (flags & XDP_TXMD_FLAGS_LAUNCH_TIME))
		return -EOPNOTSUPP;

	if (!meta->request.gso_size || meta->request.gso_size == GSO_BY_FRAGS ||
	    meta->request.network_offset < ETH_HLEN ||
	    meta->request.csum_start < meta->request.network_offset ||
	    meta->request.csum_offset != offsetof(struct udphdr, check))
		return -EINVAL;
	header_len = (u32)meta->request.csum_start + sizeof(struct udphdr);
	if (header_len > XSK_TX_USO_MAX_HEADER || header_len > descs->len)
		return -EINVAL;
	for (i = 0; i < nr; i++) {
		if (check_add_overflow(len, descs[i].len, &len) ||
		    xsk_is_eop_desc(&descs[i]) != (i == nr - 1))
			return -EINVAL;
	}

	info->header_len = header_len;
	info->len = len;
	memcpy(header, xsk_buff_raw_get_data(pool, descs->addr), header_len);
	err = xsk_tx_uso_validate(header, info, READ_ONCE(pool->netdev->mtu));
	if (err)
		return err;
	/* As in copy mode, segmentation follows the device feature. */
	if (info->gso_segs > 1 &&
	    !(READ_ONCE(pool->netdev->features) & NETIF_F_GSO_UDP_L4))
		return -EOPNOTSUPP;
	return 1;
}
EXPORT_SYMBOL_GPL(xsk_tx_uso_parse);

/**
 * xsk_tx_uso_prepare_headers - prepare the copied header for hardware USO
 * @info: layout of a request validated by xsk_tx_uso_parse()
 * @header: header copied by xsk_tx_uso_parse()
 *
 * Call once after validation and before syncing the header for DMA. Removes
 * the aggregate length from the partial UDP checksum seed and clears IP
 * length/checksum fields for the segmentation engine. Single-datagram headers
 * are unchanged.
 */
void xsk_tx_uso_prepare_headers(const struct xsk_tx_uso_info *info,
				void *header)
{
	const struct xsk_tx_metadata *meta = &info->metadata;
	struct udphdr *uh = header + meta->request.csum_start;

	if (info->gso_segs == 1)
		return;
	xsk_tx_prepare_gso_headers(NULL, NULL, 0,
				   header + meta->request.network_offset,
				   &uh->check,
				   info->len - meta->request.csum_start);
}
EXPORT_SYMBOL_GPL(xsk_tx_uso_prepare_headers);
