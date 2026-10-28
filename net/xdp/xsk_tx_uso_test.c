// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/gso.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <net/xdp_sock_drv.h>
#include <net/xsk_tx_uso.h>

static void uso_packet(void *header, struct xsk_tx_uso_info *uso,
		       bool ipv6, bool vlan, u32 payload)
{
	u32 iplen = ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	struct xsk_tx_metadata *meta = &uso->metadata;
	struct ethhdr *eth = header;
	struct udphdr *uh;

	memset(header, 0, 128);
	memset(uso, 0, sizeof(*uso));
	meta->request.network_offset = ETH_HLEN + (vlan ? VLAN_HLEN : 0);
	meta->request.csum_start = meta->request.network_offset + iplen;
	uso->header_len = meta->request.csum_start + sizeof(*uh);
	uso->len = uso->header_len + payload;
	meta->request.gso_size = 1400;
	eth->h_proto = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP);
	if (vlan) {
		struct vlan_hdr *vh = header + ETH_HLEN;

		vh->h_vlan_encapsulated_proto = eth->h_proto;
		eth->h_proto = htons(ETH_P_8021Q);
	}
	if (ipv6) {
		struct ipv6hdr *ip6h = header + meta->request.network_offset;

		ip6h->version = 6;
		ip6h->nexthdr = IPPROTO_UDP;
		ip6h->payload_len = htons(sizeof(*uh) + payload);
	} else {
		struct iphdr *iph = header + meta->request.network_offset;

		iph->version = 4;
		iph->ihl = 5;
		iph->protocol = IPPROTO_UDP;
		iph->tot_len = htons(iplen + sizeof(*uh) + payload);
	}
	uh = header + meta->request.csum_start;
	uh->len = htons(sizeof(*uh) + payload);
}

static void uso_valid(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + 128] __aligned(4);
	struct xsk_tx_uso_info uso;
	int ipv6, vlan;
	void *header;

	header = storage + NET_IP_ALIGN;
	for (ipv6 = 0; ipv6 < 2; ipv6++)
		for (vlan = 0; vlan < 2; vlan++) {
			uso_packet(header, &uso, ipv6, vlan, 4000);
			KUNIT_ASSERT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
			KUNIT_EXPECT_EQ(test, uso.gso_segs, 3);
			KUNIT_EXPECT_EQ(test, uso.protocol, htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP));
			uso_packet(header, &uso, ipv6, vlan, 0);
			KUNIT_ASSERT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
			KUNIT_EXPECT_EQ(test, uso.gso_segs, 1);
		}
}

static void uso_invalid(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + 128] __aligned(4);
	struct xsk_tx_uso_info uso;
	struct iphdr *iph;
	struct udphdr *uh;
	void *header;
	int kind;

	header = storage + NET_IP_ALIGN;
	for (kind = 0; kind < 8; kind++) {
		uso_packet(header, &uso, false, false, 4000);
		iph = header + uso.metadata.request.network_offset;
		uh = header + uso.metadata.request.csum_start;
		switch (kind) {
		case 0:
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
			uso.metadata.request.network_offset++;
			break;
		case 7:
			uso.len = uso.header_len - 1;
			break;
		}
		KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
	}
	uso_packet(header, &uso, true, false, 4000);
	((struct ipv6hdr *)(header + uso.metadata.request.network_offset))->nexthdr =
		IPPROTO_DSTOPTS;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
}

static void uso_limits(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + 128] __aligned(4);
	struct xsk_tx_uso_info uso;
	void *header;

	header = storage + NET_IP_ALIGN;
	uso_packet(header, &uso, false, false, 8192);
	uso.metadata.request.gso_size = 64;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
	KUNIT_EXPECT_EQ(test, uso.gso_segs, UDP_MAX_SEGMENTS);
	uso_packet(header, &uso, false, false, 8193);
	uso.metadata.request.gso_size = 64;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
	uso_packet(header, &uso, false, false, 4000);
	uso.metadata.request.gso_size = 1472;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), 0);
	uso.metadata.request.gso_size++;
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
}

static void uso_header_layout(struct kunit *test)
{
	u8 storage[NET_IP_ALIGN + 128] __aligned(4);
	struct xsk_tx_uso_info uso;
	struct vlan_hdr *vh;
	struct udphdr *uh;
	struct iphdr *iph;
	void *header;

	header = storage + NET_IP_ALIGN;
	uso_packet(header, &uso, false, false, 4000);
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
	uso_packet(header, &uso, false, true, 4000);
	vh = header + ETH_HLEN;
	vh->h_vlan_encapsulated_proto = htons(ETH_P_8021Q);
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
	uso_packet(header, &uso, false, true, 4000);
	uso.metadata.request.csum_start = ETH_HLEN;
	uso.header_len = ETH_HLEN + sizeof(*uh);
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500), -EINVAL);
	uso_packet(header, &uso, false, false, 4000);
	((struct ethhdr *)header)->h_proto = htons(ETH_P_ARP);
	KUNIT_EXPECT_EQ(test, xsk_tx_uso_validate(header, &uso, 1500),
			-EPROTONOSUPPORT);
}

static void uso_prepare_headers(struct kunit *test)
{
	struct xsk_tx_uso uso;
	int ipv6;

	for (ipv6 = 0; ipv6 < 2; ipv6++) {
		struct udphdr *uh;
		__sum16 check;
		void *header;

		header = xsk_tx_uso_header(&uso);
		uso_packet(header, &uso.info, ipv6, false, 4000);
		KUNIT_ASSERT_EQ(test, xsk_tx_uso_validate(header, &uso.info, 1500), 0);

		uh = header + uso.info.metadata.request.csum_start;
		uh->check = htons(0x1234);
		check = uh->check;
		csum_replace_by_diff(&check, (__force __wsum)htonl(uso.info.len -
			uso.info.metadata.request.csum_start));

		xsk_tx_uso_prepare_headers(&uso);
		KUNIT_EXPECT_EQ(test, uh->check, check);
		if (ipv6) {
			struct ipv6hdr *ip6h = header +
				uso.info.metadata.request.network_offset;

			KUNIT_EXPECT_EQ(test, ip6h->payload_len, 0);
		} else {
			struct iphdr *iph = header +
				uso.info.metadata.request.network_offset;

			KUNIT_EXPECT_EQ(test, iph->tot_len, 0);
			KUNIT_EXPECT_EQ(test, iph->check, 0);
		}
	}
}

static void uso_prepare_outer_headers(struct kunit *test)
{
	struct iphdr outer_ip = {
		.version = 4,
		.tot_len = htons(4096),
		.check = htons(0x1234),
	};
	struct udphdr outer_udp = {
		.len = htons(4096),
		.check = htons(0x2345),
	};
	struct iphdr inner_ip = {
		.version = 4,
		.tot_len = htons(2048),
		.check = htons(0x3456),
	};
	__sum16 outer_check = outer_udp.check;
	__sum16 inner_check = htons(0x4567);
	__sum16 expected_inner_check = inner_check;

	csum_replace_by_diff(&outer_check, (__force __wsum)htonl(8192));
	csum_replace_by_diff(&expected_inner_check, (__force __wsum)htonl(2048));
	xsk_tx_prepare_gso_headers(&outer_ip, &outer_udp, 8192, &inner_ip,
				   &inner_check, 2048);

	KUNIT_EXPECT_EQ(test, outer_ip.tot_len, 0);
	KUNIT_EXPECT_EQ(test, outer_ip.check, 0);
	KUNIT_EXPECT_EQ(test, outer_udp.len, 0);
	KUNIT_EXPECT_EQ(test, outer_udp.check, outer_check);
	KUNIT_EXPECT_EQ(test, inner_ip.tot_len, 0);
	KUNIT_EXPECT_EQ(test, inner_ip.check, 0);
	KUNIT_EXPECT_EQ(test, inner_check, expected_inner_check);
}

static void uso_snapshot(struct kunit *test)
{
	struct xdp_desc descs[2] = {
		{ .addr = 128, .len = 2048, .options = XDP_TX_METADATA | XDP_PKT_CONTD },
		{ .addr = 4096, .len = 1994 },
	};
	struct xsk_tx_metadata meta = {
		.flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM,
		.request = {
			.csum_start = 34,
			.csum_offset = offsetof(struct udphdr, check),
			.gso_size = 1400,
			.network_offset = ETH_HLEN,
		},
	};
	struct xsk_tx_uso original, copy;
	struct xsk_buff_pool *pool;
	struct udphdr *uh;
	void *header;
	int kind;

	pool = kunit_kzalloc(test, sizeof(*pool), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pool);
	pool->netdev = kunit_kzalloc(test, sizeof(*pool->netdev), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pool->netdev);
	pool->netdev->type = ARPHRD_ETHER;
	pool->netdev->mtu = 1500;
	pool->tx_metadata_len = 16;
	pool->tx_uso_supported = true;
	pool->addrs = kunit_kzalloc(test, 8192, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pool->addrs);
	uso_packet(xsk_tx_uso_header(&original), &original.info, false, false, 4000);
	header = pool->addrs + descs[0].addr;
	memcpy(header - 16, &meta, 16);
	memcpy(header, xsk_tx_uso_header(&original), original.info.header_len);
	KUNIT_ASSERT_PTR_EQ(test,
			    xsk_tx_uso_parse(pool, descs, ARRAY_SIZE(descs),
					     &copy), &copy);

	memset(header - 16, 0xff, original.info.header_len + 16);
	KUNIT_EXPECT_MEMEQ(test, xsk_tx_uso_header(&copy),
			   xsk_tx_uso_header(&original), original.info.header_len);
	xsk_tx_uso_prepare_headers(&copy);
	uh = xsk_tx_uso_header(&copy) + copy.info.metadata.request.csum_start;
	KUNIT_EXPECT_EQ(test, ((struct iphdr *)(xsk_tx_uso_header(&copy) +
			copy.info.metadata.request.network_offset))->tot_len, 0);
	KUNIT_EXPECT_EQ(test, uh->len, htons(4008));
	KUNIT_EXPECT_EQ(test, *(u8 *)header, 0xff);

	memcpy(header, xsk_tx_uso_header(&original), original.info.header_len);
	for (kind = 0; kind < 4; kind++) {
		meta.request.gso_size = 1400;
		meta.request.network_offset = ETH_HLEN;
		meta.request.csum_start = 34;
		switch (kind) {
		case 0:
			meta.request.gso_size = 0;
			break;
		case 1:
			meta.request.gso_size = GSO_BY_FRAGS;
			break;
		case 2:
			meta.request.network_offset = 0;
			break;
		case 3:
			meta.request.csum_start = U16_MAX;
			break;
		}
		memcpy(header - 16, &meta, 16);
		KUNIT_EXPECT_EQ(test,
				PTR_ERR(xsk_tx_uso_parse(pool, descs, 2, &copy)),
				-EINVAL);
	}
	meta.flags = XDP_TXMD_FLAGS_CHECKSUM;
	memcpy(header - 16, &meta, 16);
	KUNIT_EXPECT_PTR_EQ(test, xsk_tx_uso_parse(pool, descs, 2, &copy), NULL);
}

static struct kunit_case xsk_tx_uso_cases[] = {
	KUNIT_CASE(uso_valid),
	KUNIT_CASE(uso_invalid),
	KUNIT_CASE(uso_limits),
	KUNIT_CASE(uso_header_layout),
	KUNIT_CASE(uso_prepare_headers),
	KUNIT_CASE(uso_prepare_outer_headers),
	KUNIT_CASE(uso_snapshot),
	{}
};

static struct kunit_suite xsk_tx_uso_suite = {
	.name = "xsk_tx_uso",
	.test_cases = xsk_tx_uso_cases,
};

kunit_test_suite(xsk_tx_uso_suite);
MODULE_LICENSE("GPL");
