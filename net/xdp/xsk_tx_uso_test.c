// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <net/xdp_sock_drv.h>
#include <net/xsk_tx_uso.h>

#define USO_META_LEN	sizeof(struct xsk_tx_metadata)

static const __be32 uso_saddr = cpu_to_be32(0xc0a80001);
static const __be32 uso_daddr = cpu_to_be32(0xc0a80002);

/* Build an Ethernet frame with @l2_len bytes of link layer, one IP header and
 * a UDP header carrying @payload bytes, and describe it in @uso.
 */
static void uso_packet(void *header, struct xsk_tx_uso_info *uso,
		       bool ipv6, u32 l2_len, u32 payload)
{
	u32 iplen = ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	struct xsk_tx_metadata *meta = &uso->metadata;
	struct ethhdr *eth = header;
	struct udphdr *uh;

	memset(header, 0, XSK_TX_USO_MAX_HEADER);
	memset(uso, 0, sizeof(*uso));
	meta->request.network_offset = l2_len;
	meta->request.csum_start = l2_len + iplen;
	meta->request.csum_offset = offsetof(struct udphdr, check);
	meta->request.gso_size = 1400;
	uso->header_len = meta->request.csum_start + sizeof(*uh);
	uso->len = uso->header_len + payload;
	eth->h_proto = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP);
	if (ipv6) {
		struct ipv6hdr *ip6h = header + l2_len;

		ip6h->version = 6;
		ip6h->nexthdr = IPPROTO_UDP;
		ip6h->payload_len = htons(sizeof(*uh) + payload);
		ip6h->saddr.s6_addr32[0] = uso_saddr;
		ip6h->daddr.s6_addr32[0] = uso_daddr;
	} else {
		struct iphdr *iph = header + l2_len;

		iph->version = 4;
		iph->ihl = 5;
		iph->protocol = IPPROTO_UDP;
		iph->tot_len = htons(iplen + sizeof(*uh) + payload);
		iph->saddr = uso_saddr;
		iph->daddr = uso_daddr;
	}
	uh = header + meta->request.csum_start;
	uh->len = htons(sizeof(*uh) + payload);
}

/* Partial pseudo-header checksum over a UDP length, as an application seeds it. */
static __sum16 uso_pseudo_csum(void *header, const struct xsk_tx_uso_info *uso,
			       bool ipv6, u32 udp_len)
{
	void *ip = header + uso->metadata.request.network_offset;

	if (ipv6) {
		struct ipv6hdr *ip6h = ip;

		return ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, udp_len,
					IPPROTO_UDP, 0);
	}
	return ~csum_tcpudp_magic(((struct iphdr *)ip)->saddr,
				  ((struct iphdr *)ip)->daddr, udp_len,
				  IPPROTO_UDP, 0);
}

static void uso_valid(struct kunit *test)
{
	static const u32 l2_lens[] = { ETH_HLEN, ETH_HLEN + VLAN_HLEN,
				       ETH_HLEN + 8 };
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info uso;
	int ipv6, i;

	for (ipv6 = 0; ipv6 < 2; ipv6++)
		for (i = 0; i < ARRAY_SIZE(l2_lens); i++) {
			uso_packet(header, &uso, ipv6, l2_lens[i], 4000);
			KUNIT_ASSERT_EQ_MSG(test,
					    xsk_tx_uso_validate(header, &uso, 1500),
					    0, "ipv6 %d l2 %u", ipv6, l2_lens[i]);
			KUNIT_EXPECT_EQ(test, uso.gso_segs, 3);
			KUNIT_EXPECT_EQ(test, uso.protocol,
					htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP));
			KUNIT_EXPECT_EQ(test, uso.l4_protocol, IPPROTO_UDP);
			KUNIT_EXPECT_EQ(test, uso.l4_len, sizeof(struct udphdr));
			uso_packet(header, &uso, ipv6, l2_lens[i], 0);
			KUNIT_ASSERT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500),
					0);
			KUNIT_EXPECT_EQ(test, uso.gso_segs, 1);
		}
}

static void uso_invalid(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info uso;
	struct iphdr *iph;
	struct udphdr *uh;
	int kind;

	for (kind = 0; kind < 9; kind++) {
		uso_packet(header, &uso, false, ETH_HLEN, 4000);
		iph = header + uso.metadata.request.network_offset;
		uh = header + uso.metadata.request.csum_start;
		switch (kind) {
		case 0:
			/* An IPv6 version needs a 40-byte network header. */
			iph->version = 6;
			break;
		case 1:
			iph->ihl = 4;
			break;
		case 2:
			iph->tot_len = htons(40);
			break;
		case 3:
			iph->frag_off = htons(IP_MF);
			break;
		case 4:
			iph->protocol = IPPROTO_TCP;
			break;
		case 5:
			uh->len = htons(8);
			break;
		case 6:
			uso.metadata.request.network_offset = ETH_HLEN - 1;
			break;
		case 7:
			uso.metadata.request.network_offset =
				uso.metadata.request.csum_start;
			break;
		case 8:
			uso.len = uso.header_len - 1;
			break;
		}
		KUNIT_EXPECT_EQ_MSG(test, xsk_tx_uso_validate(header, &uso, 1500),
				    -EINVAL, "kind %d", kind);
	}
	uso_packet(header, &uso, true, ETH_HLEN, 4000);
	((struct ipv6hdr *)(header + ETH_HLEN))->nexthdr = IPPROTO_DSTOPTS;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
}

static void uso_limits(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info uso;

	uso_packet(header, &uso, false, ETH_HLEN, 8192);
	uso.metadata.request.gso_size = 64;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
	KUNIT_EXPECT_EQ(test, uso.gso_segs, UDP_MAX_SEGMENTS);
	uso_packet(header, &uso, false, ETH_HLEN, 8193);
	uso.metadata.request.gso_size = 64;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
	uso_packet(header, &uso, false, ETH_HLEN, 4000);
	uso.metadata.request.gso_size = 1472;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
	uso.metadata.request.gso_size++;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
	/* A single datagram must fit the MTU as well. */
	uso_packet(header, &uso, false, ETH_HLEN, 1473);
	uso.metadata.request.gso_size = 4000;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
}

static void uso_header_layout(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info uso;
	struct udphdr *uh;
	struct iphdr *iph;

	/* IPv4 options are accepted when csum_start points past them. */
	uso_packet(header, &uso, false, ETH_HLEN, 4000);
	iph = header + uso.metadata.request.network_offset;
	memmove(header + uso.metadata.request.csum_start + 4,
		header + uso.metadata.request.csum_start, sizeof(*uh));
	memset(header + uso.metadata.request.csum_start, 0, 4);
	iph->ihl++;
	iph->tot_len = htons(ntohs(iph->tot_len) + 4);
	uso.metadata.request.csum_start += 4;
	uso.header_len += 4;
	uso.len += 4;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);

	/* The link layer is not parsed: the IP header is found at
	 * network_offset whatever the EtherType says. Copy mode checks the
	 * EtherType separately.
	 */
	uso_packet(header, &uso, false, ETH_HLEN + VLAN_HLEN, 4000);
	((struct ethhdr *)header)->h_proto = htons(ETH_P_ARP);
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
	KUNIT_EXPECT_EQ(test, uso.protocol, htons(ETH_P_IP));

	/* The IP version selects the protocol. */
	uso_packet(header, &uso, false, ETH_HLEN, 4000);
	((struct iphdr *)(header + ETH_HLEN))->version = 5;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500),
			-EPROTONOSUPPORT);
}

static void uso_prepare_headers(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info uso;
	int ipv6;

	for (ipv6 = 0; ipv6 < 2; ipv6++) {
		void *ip = header + ETH_HLEN;
		struct udphdr *uh;
		u32 udp_len;

		uso_packet(header, &uso, ipv6, ETH_HLEN, 4000);
		KUNIT_ASSERT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
		uh = header + uso.metadata.request.csum_start;
		udp_len = uso.len - uso.metadata.request.csum_start;
		uh->check = uso_pseudo_csum(header, &uso, ipv6, udp_len);

		/* The seed must cover the pseudo header without the length. */
		xsk_tx_uso_prepare_headers(&uso, header);
		KUNIT_EXPECT_EQ_MSG(test, uh->check,
				    uso_pseudo_csum(header, &uso, ipv6, 0),
				    "ipv6 %d", ipv6);
		if (ipv6) {
			KUNIT_EXPECT_EQ(test, ((struct ipv6hdr *)ip)->payload_len,
					0);
		} else {
			KUNIT_EXPECT_EQ(test, ((struct iphdr *)ip)->tot_len, 0);
			KUNIT_EXPECT_EQ(test, ((struct iphdr *)ip)->check, 0);
		}
	}
}

/* A single datagram uses ordinary checksum offload, so its headers stay. */
static void uso_prepare_single(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	u8 orig[XSK_TX_USO_MAX_HEADER];
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info uso;
	struct udphdr *uh;

	uso_packet(header, &uso, false, ETH_HLEN, 1000);
	KUNIT_ASSERT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
	KUNIT_ASSERT_EQ(test, uso.gso_segs, 1);
	uh = header + uso.metadata.request.csum_start;
	uh->check = uso_pseudo_csum(header, &uso, false, ntohs(uh->len));
	memcpy(orig, header, uso.header_len);
	xsk_tx_uso_prepare_headers(&uso, header);
	KUNIT_EXPECT_MEMEQ(test, header, orig, uso.header_len);
}

static void uso_prepare_outer_headers(struct kunit *test)
{
	struct iphdr outer_ip = {
		.version = 4,
		.tot_len = htons(4096),
		.check = htons(0x1234),
		.saddr = uso_saddr,
		.daddr = uso_daddr,
	};
	struct udphdr outer_udp = {
		.len = htons(4096),
	};
	struct iphdr inner_ip = {
		.version = 4,
		.tot_len = htons(2048),
		.check = htons(0x3456),
		.saddr = uso_daddr,
		.daddr = uso_saddr,
	};
	__sum16 inner_check;

	outer_udp.check = ~csum_tcpudp_magic(uso_saddr, uso_daddr, 8192,
					     IPPROTO_UDP, 0);
	inner_check = ~csum_tcpudp_magic(uso_daddr, uso_saddr, 2048,
					 IPPROTO_TCP, 0);
	xsk_tx_prepare_gso_headers(&outer_ip, &outer_udp, 8192, &inner_ip,
				   &inner_check, 2048);

	KUNIT_EXPECT_EQ(test, outer_ip.tot_len, 0);
	KUNIT_EXPECT_EQ(test, outer_ip.check, 0);
	KUNIT_EXPECT_EQ(test, outer_udp.len, 0);
	KUNIT_EXPECT_EQ(test, outer_udp.check,
			(__sum16)~csum_tcpudp_magic(uso_saddr, uso_daddr, 0,
						    IPPROTO_UDP, 0));
	KUNIT_EXPECT_EQ(test, inner_ip.tot_len, 0);
	KUNIT_EXPECT_EQ(test, inner_ip.check, 0);
	KUNIT_EXPECT_EQ(test, inner_check,
			(__sum16)~csum_tcpudp_magic(uso_daddr, uso_saddr, 0,
						    IPPROTO_TCP, 0));
}

static void uso_metadata_flags(struct kunit *test)
{
	struct xsk_tx_metadata meta = {
		.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM,
	};
	struct xsk_buff_pool *pool;
	u64 flags;

	pool = kunit_kzalloc(test, sizeof(*pool), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pool);
	pool->tx_metadata_len = USO_META_LEN;
	pool->tx_uso_supported = true;

	KUNIT_ASSERT_TRUE(test, xsk_buff_valid_tx_metadata(pool, &meta, &flags));
	KUNIT_EXPECT_TRUE(test, xsk_tx_uso_flags_valid(flags));

	/* USO needs checksum offload and cannot report a Tx timestamp. */
	meta.flags = XDP_TXMD_FLAGS_USO;
	KUNIT_ASSERT_TRUE(test, xsk_buff_valid_tx_metadata(pool, &meta, &flags));
	KUNIT_EXPECT_FALSE(test, xsk_tx_uso_flags_valid(flags));
	meta.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM |
		     XDP_TXMD_FLAGS_TIMESTAMP;
	KUNIT_ASSERT_TRUE(test, xsk_buff_valid_tx_metadata(pool, &meta, &flags));
	KUNIT_EXPECT_FALSE(test, xsk_tx_uso_flags_valid(flags));

	/* Launch time is allowed here; zero-copy rejects it when parsing. */
	meta.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM |
		     XDP_TXMD_FLAGS_LAUNCH_TIME;
	KUNIT_ASSERT_TRUE(test, xsk_buff_valid_tx_metadata(pool, &meta, &flags));
	KUNIT_EXPECT_TRUE(test, xsk_tx_uso_flags_valid(flags));

	/* USO requests are refused on pools that cannot carry them. */
	meta.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM;
	pool->tx_uso_supported = false;
	KUNIT_EXPECT_FALSE(test, xsk_buff_valid_tx_metadata(pool, &meta, &flags));
	pool->tx_uso_supported = true;
	pool->tx_metadata_len =
		offsetofend(struct xsk_tx_metadata, request.network_offset) - 1;
	KUNIT_EXPECT_FALSE(test, xsk_buff_valid_tx_metadata(pool, &meta, &flags));
	pool->tx_metadata_len = USO_META_LEN;
	meta.flags |= BIT_ULL(63);
	KUNIT_EXPECT_FALSE(test, xsk_buff_valid_tx_metadata(pool, &meta, &flags));
}

struct uso_parse_ctx {
	struct xsk_buff_pool *pool;
	struct xdp_desc descs[2];
	u32 nr;
	struct xsk_tx_metadata meta;
	struct xsk_tx_uso_info orig;
	u8 orig_header[XSK_TX_USO_MAX_HEADER];
	void *umem_header;
};

/* Place a packet with @payload bytes in a UMEM, split over two descriptors
 * when it does not fit in the first 2048 bytes.
 */
static void uso_parse_init(struct kunit *test, struct uso_parse_ctx *ctx,
			   u32 payload)
{
	struct xsk_buff_pool *pool;

	memset(ctx, 0, sizeof(*ctx));
	pool = kunit_kzalloc(test, sizeof(*pool), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pool);
	pool->netdev = kunit_kzalloc(test, sizeof(*pool->netdev), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pool->netdev);
	pool->netdev->mtu = 1500;
	pool->netdev->features = NETIF_F_GSO_UDP_L4;
	pool->tx_metadata_len = USO_META_LEN;
	pool->tx_uso_supported = true;
	pool->addrs = kunit_kzalloc(test, 8192, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pool->addrs);
	ctx->pool = pool;

	uso_packet(ctx->orig_header, &ctx->orig, false, ETH_HLEN, payload);
	ctx->nr = ctx->orig.len > 2048 ? 2 : 1;
	ctx->descs[0] = (struct xdp_desc) {
		.addr = 128, .len = min(ctx->orig.len, 2048U),
		.options = XDP_TX_METADATA | (ctx->nr > 1 ? XDP_PKT_CONTD : 0),
	};
	ctx->descs[1] = (struct xdp_desc) {
		.addr = 4096, .len = ctx->orig.len - ctx->descs[0].len,
	};
	ctx->meta = ctx->orig.metadata;
	ctx->meta.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM;
	ctx->umem_header = pool->addrs + ctx->descs[0].addr;
	memcpy(ctx->umem_header, ctx->orig_header, ctx->orig.header_len);
}

static int uso_parse(struct uso_parse_ctx *ctx, struct xsk_tx_uso_info *info,
		     void *header)
{
	memcpy(ctx->umem_header - USO_META_LEN, &ctx->meta, USO_META_LEN);
	return xsk_tx_uso_parse(ctx->pool, ctx->descs, ctx->nr, info, header);
}

static void uso_snapshot(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info info;
	struct uso_parse_ctx ctx;
	struct udphdr *uh;

	uso_parse_init(test, &ctx, 4000);
	KUNIT_ASSERT_EQ(test, uso_parse(&ctx, &info, header), 1);
	KUNIT_EXPECT_EQ(test, info.len, ctx.orig.len);
	KUNIT_EXPECT_EQ(test, info.header_len, ctx.orig.header_len);
	KUNIT_EXPECT_EQ(test, info.gso_segs, 3);

	/* Changes to the UMEM after parsing do not reach the copy. */
	memset(ctx.umem_header - USO_META_LEN, 0xff,
	       USO_META_LEN + ctx.orig.header_len);
	KUNIT_EXPECT_MEMEQ(test, header, ctx.orig_header, ctx.orig.header_len);
	KUNIT_EXPECT_EQ(test, info.metadata.request.gso_size, 1400);

	/* Preparing the copy leaves the UMEM alone. */
	xsk_tx_uso_prepare_headers(&info, header);
	uh = header + info.metadata.request.csum_start;
	KUNIT_EXPECT_EQ(test, ((struct iphdr *)(header + ETH_HLEN))->tot_len, 0);
	KUNIT_EXPECT_EQ(test, uh->len, htons(4008));
	KUNIT_EXPECT_EQ(test, *(u8 *)ctx.umem_header, 0xff);
}

static void uso_parse_invalid(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info info;
	struct uso_parse_ctx ctx;
	int kind;

	for (kind = 0; kind < 7; kind++) {
		uso_parse_init(test, &ctx, 4000);
		switch (kind) {
		case 0:
			ctx.meta.request.gso_size = 0;
			break;
		case 1:
			ctx.meta.request.gso_size = GSO_BY_FRAGS;
			break;
		case 2:
			ctx.meta.request.network_offset = 0;
			break;
		case 3:
			ctx.meta.request.csum_start = XSK_TX_USO_MAX_HEADER;
			break;
		case 4:
			ctx.meta.request.csum_offset = 0;
			break;
		case 5:
			/* All headers through UDP must be in the first buffer. */
			ctx.descs[0].len = ctx.orig.header_len - 1;
			ctx.descs[1].len = ctx.orig.len - ctx.descs[0].len;
			break;
		case 6:
			/* Only the last descriptor may end the packet. */
			ctx.descs[0].options &= ~XDP_PKT_CONTD;
			break;
		}
		KUNIT_EXPECT_EQ_MSG(test, uso_parse(&ctx, &info, header), -EINVAL,
				    "kind %d", kind);
	}

	/* Rejected flag combinations. */
	uso_parse_init(test, &ctx, 4000);
	ctx.meta.flags = XDP_TXMD_FLAGS_USO;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), -EOPNOTSUPP);
	ctx.meta.flags |= XDP_TXMD_FLAGS_CHECKSUM | XDP_TXMD_FLAGS_TIMESTAMP;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), -EOPNOTSUPP);
	ctx.meta.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM |
			 XDP_TXMD_FLAGS_LAUNCH_TIME;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), -EOPNOTSUPP);

	/* A header the validator rejects. */
	uso_parse_init(test, &ctx, 4000);
	((struct iphdr *)(ctx.umem_header + ETH_HLEN))->protocol = IPPROTO_TCP;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), -EINVAL);
}

static void uso_parse_feature(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info info;
	struct uso_parse_ctx ctx;

	/* Segmentation follows NETIF_F_GSO_UDP_L4. */
	uso_parse_init(test, &ctx, 4000);
	ctx.pool->netdev->features = 0;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), -EOPNOTSUPP);

	/* A single datagram does not need it. */
	uso_parse_init(test, &ctx, 1000);
	ctx.pool->netdev->features = 0;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), 1);
	KUNIT_EXPECT_EQ(test, info.gso_segs, 1);
}

static void uso_parse_no_uso(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + XSK_TX_USO_MAX_HEADER] __aligned(4);
	void *header = storage + NET_IP_ALIGN;
	struct xsk_tx_uso_info info;
	struct uso_parse_ctx ctx;

	uso_parse_init(test, &ctx, 4000);
	ctx.meta.flags = XDP_TXMD_FLAGS_CHECKSUM;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), 0);
	ctx.meta.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM;
	ctx.descs[0].options &= ~XDP_TX_METADATA;
	KUNIT_EXPECT_EQ(test, uso_parse(&ctx, &info, header), 0);
}

static struct kunit_case xsk_tx_uso_cases[] = {
	KUNIT_CASE(uso_valid),
	KUNIT_CASE(uso_invalid),
	KUNIT_CASE(uso_limits),
	KUNIT_CASE(uso_header_layout),
	KUNIT_CASE(uso_prepare_headers),
	KUNIT_CASE(uso_prepare_single),
	KUNIT_CASE(uso_prepare_outer_headers),
	KUNIT_CASE(uso_metadata_flags),
	KUNIT_CASE(uso_snapshot),
	KUNIT_CASE(uso_parse_invalid),
	KUNIT_CASE(uso_parse_feature),
	KUNIT_CASE(uso_parse_no_uso),
	{}
};

static struct kunit_suite xsk_tx_uso_suite = {
	.name = "xsk_tx_uso",
	.test_cases = xsk_tx_uso_cases,
};

kunit_test_suite(xsk_tx_uso_suite);
MODULE_DESCRIPTION("KUnit tests for AF_XDP USO header helpers");
MODULE_LICENSE("GPL");
