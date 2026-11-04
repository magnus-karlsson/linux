// SPDX-License-Identifier: GPL-2.0
#include <linux/if_vlan.h>
#include <linux/unaligned.h>
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
 * The caller must provide a nonzero gso_size other than GSO_BY_FRAGS,
 * network_offset >= ETH_HLEN, and header_len equal to transport_offset plus
 * the UDP header size.
 *
 * Return: zero on success or a negative error code.
 */
int xsk_tx_uso_validate(const void *header, struct xsk_tx_uso_info *uso, u32 mtu)
{
	const struct xsk_tx_metadata *meta = &uso->metadata;
	u32 thoff = meta->request.csum_start;
	u32 nhoff = meta->request.network_offset;
	u32 network_len, depth = ETH_HLEN;
	u32 udp_len, payload_len;
	const struct udphdr *uh;
	__be16 protocol;
	int tags = 0;

	if (thoff < ETH_HLEN || uso->header_len < thoff ||
	    uso->len < uso->header_len)
		return -EINVAL;

	protocol = get_unaligned((const __be16 *)(header + 2 * ETH_ALEN));
	while (eth_type_vlan(protocol)) {
		if (++tags > VLAN_MAX_DEPTH || depth + VLAN_HLEN > thoff)
			return -EINVAL;
		protocol = get_unaligned((const __be16 *)(header + depth + 2));
		depth += VLAN_HLEN;
	}
	if (nhoff && depth != nhoff)
		return -EINVAL;
	nhoff = depth;

	network_len = uso->len - nhoff;
	switch (protocol) {
	case htons(ETH_P_IP): {
		const struct iphdr *iph = header + nhoff;

		if (thoff - nhoff < sizeof(*iph) || iph->version != 4 ||
		    iph->ihl < 5 || iph->ihl * 4 != thoff - nhoff ||
		    ip_is_fragment(iph) ||
		    ntohs(iph->tot_len) != network_len)
			return -EINVAL;
		uso->l4_protocol = iph->protocol;
		break;
	}
	case htons(ETH_P_IPV6): {
		const struct ipv6hdr *ip6h = header + nhoff;

		if (thoff - nhoff != sizeof(*ip6h) || ip6h->version != 6 ||
		    ntohs(ip6h->payload_len) != network_len - sizeof(*ip6h))
			return -EINVAL;
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
 * @uso: caller-provided storage for the packet metadata and header
 *
 * Metadata is snapshotted before using its offsets. The packet header is
 * copied exactly once, before any parsing. The storage must remain valid until
 * DMA completes if this packet is transmitted.
 *
 * Return: @uso on success, NULL without USO, or an ERR_PTR on failure.
 */
struct xsk_tx_uso *xsk_tx_uso_parse(struct xsk_buff_pool *pool, const struct xdp_desc *descs,
				    u32 nr, struct xsk_tx_uso *uso)
{
	struct xsk_tx_metadata *user_meta;
	struct xsk_tx_metadata *meta = &uso->info.metadata;
	u32 header_len, len = 0, i;
	u64 flags;
	int err;

	user_meta = xsk_buff_get_metadata(pool, descs->addr, descs->options);
	if (!user_meta)
		return NULL;
	memcpy(meta, user_meta, min_t(size_t, pool->tx_metadata_len, sizeof(*meta)));
	if (!(meta->flags & XDP_TXMD_FLAGS_USO))
		return NULL;
	if (!xsk_buff_valid_tx_metadata(pool, meta, &flags) ||
	    !(flags & XDP_TXMD_FLAGS_CHECKSUM) ||
	    (flags & (XDP_TXMD_FLAGS_TIMESTAMP | XDP_TXMD_FLAGS_LAUNCH_TIME)) ||
	    !pool->tx_uso_supported)
		return ERR_PTR(-EOPNOTSUPP);

	if (!meta->request.gso_size || meta->request.gso_size == GSO_BY_FRAGS ||
	    meta->request.network_offset < ETH_HLEN ||
	    meta->request.csum_start < meta->request.network_offset ||
	    meta->request.csum_offset != offsetof(struct udphdr, check))
		return ERR_PTR(-EINVAL);
	header_len = (u32)meta->request.csum_start + sizeof(struct udphdr);
	if (header_len > XSK_TX_USO_MAX_HEADER || header_len > descs->len)
		return ERR_PTR(-EINVAL);
	for (i = 0; i < nr; i++) {
		if (check_add_overflow(len, descs[i].len, &len) ||
		    xsk_is_eop_desc(&descs[i]) != (i == nr - 1))
			return ERR_PTR(-EINVAL);
	}

	uso->info.header_len = header_len;
	uso->info.len = len;
	memcpy(xsk_tx_uso_header(uso), xsk_buff_raw_get_data(pool, descs->addr),
	       header_len);
	err = xsk_tx_uso_validate(xsk_tx_uso_header(uso), &uso->info,
				  READ_ONCE(pool->netdev->mtu));
	if (err)
		return ERR_PTR(err);
	return uso;
}
EXPORT_SYMBOL_GPL(xsk_tx_uso_parse);

/**
 * xsk_tx_uso_prepare_headers - prepare the copied header for hardware USO
 * @uso: validated packet returned by xsk_tx_uso_parse()
 *
 * Call once after validation and before syncing the header for DMA. Removes the aggregate
 * length from the partial UDP checksum seed and clears IP length/checksum
 * fields for the segmentation engine. Single-datagram headers are unchanged.
 */
void xsk_tx_uso_prepare_headers(struct xsk_tx_uso *uso)
{
	struct udphdr *uh;
	const struct xsk_tx_metadata *meta = &uso->info.metadata;
	void *header;

	header = xsk_tx_uso_header(uso);
	uh = header + meta->request.csum_start;
	if (uso->info.gso_segs == 1)
		return;
	xsk_tx_prepare_gso_headers(NULL, NULL, 0,
				   header + meta->request.network_offset, &uh->check,
				   uso->info.len - meta->request.csum_start);
}
EXPORT_SYMBOL_GPL(xsk_tx_uso_prepare_headers);
