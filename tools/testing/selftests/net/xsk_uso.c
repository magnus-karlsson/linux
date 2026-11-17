// SPDX-License-Identifier: GPL-2.0

/* AF_XDP UDP segmentation offload (USO) test.
 *
 * Sends USO requests from an AF_XDP socket in copy or zero-copy mode and
 * checks the datagrams received on a packet socket: their number, IP and
 * UDP lengths, checksums and payload, for IPv4 and IPv6, and single and
 * multi-buffer requests. Invalid requests must be dropped and counted in
 * tx_invalid_descs.
 *
 * Needs root and an interface with MTU 1500, plus either a connected peer
 * interface (-i TX_IFACE -r RX_IFACE) or NIC loopback (-l -i IFACE).
 * Zero-copy mode (-z) also needs an XDP program on the interface.
 * Standalone checksum offload cases run only with -C.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <linux/ipv6.h>
#include <linux/sockios.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdbool.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "kselftest.h"
#include "lib/xsk/xsk.h"

#define RING_SIZE 1024
#define NUM_FRAMES 1024
#define FRAME_SIZE 4096
#define META_LEN 16
#define TEST_PORT 49732
#define TIMEOUT_MS 2000

static_assert(sizeof(struct xsk_tx_metadata) == 24, "metadata size");
static_assert(offsetof(struct xsk_tx_metadata, request.gso_size) == 12,
	      "segment size offset");
static_assert(offsetof(struct xsk_tx_metadata, request.network_offset) == 14,
	      "network header offset");
static_assert(offsetof(struct xsk_tx_metadata, request.launch_time) == 16,
	      "launch time offset");
static_assert(offsetof(struct xsk_tx_metadata, completion.tx_timestamp) == 8,
	      "timestamp offset");

enum bad_request {
	VALID, ZERO_SIZE, FRAGS_SIZE, NO_CHECKSUM, BAD_CSUM_OFFSET,
	BAD_NETWORK_OFFSET, BAD_UDP_LENGTH, FRAGMENT, BAD_PROTOCOL,
	EXT_HEADER, LARGE_SEGMENT, SHORT_HEADER, TIMESTAMP, LAUNCH_TIME,
	SW_CHECKSUM, UNKNOWN_FLAG, BAD_IP_LENGTH, BAD_IP_VERSION, BAD_IHL,
	BAD_TRANSPORT_OFFSET, TOO_MANY_SEGMENTS, IP_TUNNEL,
};

static const struct test_case {
	const char *name;
	bool ipv6;
	unsigned int payload;
	unsigned int first_len;
	enum bad_request bad;
	bool checksum_only;
} cases[] = {
	{ "IPv4 USO", false, 4000, 0, VALID, false },
	{ "IPv6 USO", true, 4000, 0, VALID, false },
	{ "IPv4 multi-buffer USO", false, 6000, 2048, VALID, false },
	{ "IPv6 multi-buffer USO", true, 6000, 2048, VALID, false },
	{ "single output datagram", false, 1400, 0, VALID, false },
	{ "empty IPv4 datagram", false, 0, 0, VALID, false },
	{ "empty IPv6 datagram", true, 0, 0, VALID, false },
	{ "checksum-only compatibility", false, 1000, 0, VALID, true },
	{ "IPv6 checksum-only", true, 1000, 0, VALID, true },
	{ "IPv4 multi-buffer checksum-only", false, 1400, 512, VALID, true },
	{ "IPv6 multi-buffer checksum-only", true, 1400, 512, VALID, true },
	{ "empty IPv4 checksum-only", false, 0, 0, VALID, true },
	{ "empty IPv6 checksum-only", true, 0, 0, VALID, true },
	{ "checksum-only invalid checksum offset", false, 1000, 0, BAD_CSUM_OFFSET, true },
	{ "checksum-only invalid UDP length", true, 1000, 0, BAD_UDP_LENGTH, true },
	{ "checksum-only split headers", false, 1000, 0, SHORT_HEADER, true },
	{ "zero segment size", false, 4000, 0, ZERO_SIZE, false },
	{ "GSO_BY_FRAGS segment size", false, 4000, 0, FRAGS_SIZE, false },
	{ "missing checksum flag", false, 6000, 2048, NO_CHECKSUM, false },
	{ "invalid checksum offset", false, 4000, 0, BAD_CSUM_OFFSET, false },
	{ "invalid IP offset", false, 4000, 0, BAD_NETWORK_OFFSET, false },
	{ "invalid UDP length", false, 6000, 2048, BAD_UDP_LENGTH, false },
	{ "fragmented IPv4", false, 4000, 0, FRAGMENT, false },
	{ "non-UDP protocol", false, 4000, 0, BAD_PROTOCOL, false },
	{ "IPv6 extension header", true, 4000, 0, EXT_HEADER, false },
	{ "segment exceeds MTU", false, 4000, 0, LARGE_SEGMENT, false },
	{ "headers split across buffers", true, 4000, 0, SHORT_HEADER, false },
	{ "USO with timestamp", false, 4000, 0, TIMESTAMP, false },
	{ "USO with launch time", false, 4000, 0, LAUNCH_TIME, false },
	{ "IPv6 USO with launch time", true, 4000, 0, LAUNCH_TIME, false },
	{ "multi-buffer USO with launch time", false, 6000, 2048, LAUNCH_TIME, false },
	{ "USO with software checksum", false, 4000, 0, SW_CHECKSUM, false },
	{ "unknown metadata flag", false, 4000, 0, UNKNOWN_FLAG, false },
	{ "invalid IPv4 total length", false, 4000, 0, BAD_IP_LENGTH, false },
	{ "invalid IPv6 payload length", true, 4000, 0, BAD_IP_LENGTH, false },
	{ "invalid IPv4 version", false, 4000, 0, BAD_IP_VERSION, false },
	{ "invalid IPv6 version", true, 4000, 0, BAD_IP_VERSION, false },
	{ "invalid IPv4 header length", false, 4000, 0, BAD_IHL, false },
	{ "UDP offset mismatch", false, 4000, 0, BAD_TRANSPORT_OFFSET, false },
	{ "too many segments", false, 4000, 0, TOO_MANY_SEGMENTS, false },
	{ "IP tunnel", false, 4000, 0, IP_TUNNEL, false },
};

struct xsk {
	int fd;
	void *umem;
	struct xsk_umem *umem_handle;
	struct xsk_socket *socket;
	struct xsk_ring_prod fill;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons cq;
};

static unsigned char tx_mac[ETH_ALEN], rx_mac[ETH_ALEN];
static bool zero_copy;
static bool checksum_tests;

static uint64_t now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		ksft_exit_fail_msg("clock_gettime: %s\n", strerror(errno));
	return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
}

static uint32_t sum_bytes(const void *data, unsigned int len)
{
	const unsigned char *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += p[0] * 256 + p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += p[0] * 256;
	return sum;
}

static uint16_t fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static uint32_t pseudo_sum(const void *ip, bool ipv6, unsigned int udp_len)
{
	const struct iphdr *h = ip;

	if (ipv6) {
		const struct ipv6hdr *h6 = ip;

		return sum_bytes(&h6->saddr, 32) + IPPROTO_UDP + udp_len;
	}
	return sum_bytes(&h->saddr, 8) + IPPROTO_UDP + udp_len;
}

static void get_mac(const char *name, unsigned char *mac)
{
	struct ifreq ifr = {};
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		ksft_exit_fail_msg("socket: %s\n", strerror(errno));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr))
		ksft_exit_fail_msg("MAC address for %s: %s\n", name, strerror(errno));
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(fd);
}

static void open_xsk(struct xsk *xsk, unsigned int ifindex, bool sw_csum)
{
	struct xsk_socket_config config = {
		.tx_size = RING_SIZE,
		.bind_flags = (zero_copy ? XDP_ZEROCOPY : XDP_COPY) | XDP_USE_SG,
	};
	struct xsk_umem_config umem_config = {
		.fill_size = RING_SIZE,
		.comp_size = RING_SIZE,
		.frame_size = FRAME_SIZE,
		.flags = XDP_UMEM_TX_METADATA_LEN,
		.tx_metadata_len = META_LEN,
	};
	int err;

	memset(xsk, 0, sizeof(*xsk));
	xsk->umem = mmap(NULL, NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (xsk->umem == MAP_FAILED)
		ksft_exit_fail_msg("mmap UMEM: %s\n", strerror(errno));
	if (sw_csum)
		umem_config.flags |= XDP_UMEM_TX_SW_CSUM;
	err = xsk_umem__create(&xsk->umem_handle, xsk->umem, NUM_FRAMES * FRAME_SIZE,
			       &xsk->fill, &xsk->cq, &umem_config);
	if (err)
		ksft_exit_fail_msg("UMEM creation: %s\n", strerror(-err));
	{
		uint64_t deadline = now_ms() + TIMEOUT_MS;

		while ((err = xsk_socket__create(&xsk->socket, ifindex, 0,
						 xsk->umem_handle, NULL, &xsk->tx,
						 &config))) {
			if (err != -EBUSY || now_ms() >= deadline)
				ksft_exit_fail_msg("socket creation: %s\n", strerror(-err));
			usleep(10000);
		}
		xsk->fd = xsk_socket__fd(xsk->socket);
	}
}

static void close_xsk(struct xsk *xsk)
{
	int err;

	xsk_socket__delete(xsk->socket);
	err = xsk_umem__delete(xsk->umem_handle);
	if (err)
		ksft_exit_fail_msg("UMEM deletion: %s\n", strerror(-err));
	munmap(xsk->umem, NUM_FRAMES * FRAME_SIZE);
}

static unsigned int
make_packet(unsigned char *packet, const struct test_case *t, unsigned int id,
	    struct xsk_tx_metadata *meta)
{
	struct ethhdr *eth = (void *)packet;
	unsigned int ip_len = t->ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	unsigned int start = sizeof(*eth) + ip_len;
	unsigned int udp_len = sizeof(struct udphdr) + t->payload;
	struct udphdr *uh = (void *)(packet + start);
	void *ip = packet + sizeof(*eth);
	unsigned int i;

	memset(packet, 0, start + udp_len);
	memcpy(eth->h_source, tx_mac, ETH_ALEN);
	memcpy(eth->h_dest, rx_mac, ETH_ALEN);
	eth->h_proto = htons(t->ipv6 ? ETH_P_IPV6 : ETH_P_IP);
	if (t->ipv6) {
		struct ipv6hdr *h = ip;

		h->version = 6;
		h->nexthdr = IPPROTO_UDP;
		h->hop_limit = 64;
		h->payload_len = htons(udp_len);
		inet_pton(AF_INET6, "2001:db8::1", &h->saddr);
		inet_pton(AF_INET6, "2001:db8::2", &h->daddr);
	} else {
		struct iphdr *h = ip;

		h->version = 4;
		h->ihl = 5;
		h->ttl = 64;
		h->protocol = IPPROTO_UDP;
		h->tot_len = htons(ip_len + udp_len);
		h->frag_off = htons(IP_DF);
		inet_pton(AF_INET, "198.18.0.1", &h->saddr);
		inet_pton(AF_INET, "198.18.0.2", &h->daddr);
		h->check = htons((uint16_t)~fold(sum_bytes(h, ip_len)));
	}
	uh->source = htons(TEST_PORT);
	uh->dest = htons(TEST_PORT);
	uh->len = htons(udp_len);
	uh->check = htons(fold(pseudo_sum(ip, t->ipv6, udp_len)));
	for (i = 0; i < t->payload; i++)
		packet[start + sizeof(*uh) + i] = (i + id * 13) % 251;

	memset(meta, 0, sizeof(*meta));
	meta->flags = XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM;
	meta->request.csum_start = start;
	meta->request.csum_offset = offsetof(struct udphdr, check);
	meta->request.gso_size = 1400;
	meta->request.network_offset = sizeof(*eth);
	if (t->checksum_only)
		meta->flags &= ~XDP_TXMD_FLAGS_USO;
	switch (t->bad) {
	case ZERO_SIZE:
		meta->request.gso_size = 0;
		break;
	case FRAGS_SIZE:
		meta->request.gso_size = UINT16_MAX;
		break;
	case NO_CHECKSUM:
		meta->flags &= ~XDP_TXMD_FLAGS_CHECKSUM;
		break;
	case BAD_CSUM_OFFSET:
		meta->request.csum_offset = 0;
		break;
	case BAD_NETWORK_OFFSET:
		meta->request.network_offset++;
		break;
	case BAD_UDP_LENGTH:
		uh->len = htons(udp_len - 1);
		break;
	case FRAGMENT:
		((struct iphdr *)ip)->frag_off = htons(IP_MF);
		break;
	case BAD_PROTOCOL:
		((struct iphdr *)ip)->protocol = IPPROTO_TCP;
		break;
	case EXT_HEADER:
		((struct ipv6hdr *)ip)->nexthdr = IPPROTO_DSTOPTS;
		break;
	case LARGE_SEGMENT:
		meta->request.gso_size = 4000;
		break;
	case TIMESTAMP:
		meta->flags |= XDP_TXMD_FLAGS_TIMESTAMP;
		break;
	case LAUNCH_TIME:
		meta->flags |= XDP_TXMD_FLAGS_LAUNCH_TIME;
		break;
	case UNKNOWN_FLAG:
		meta->flags |= 1ULL << 63;
		break;
	case BAD_IP_LENGTH:
		if (t->ipv6)
			((struct ipv6hdr *)ip)->payload_len = htons(udp_len - 1);
		else
			((struct iphdr *)ip)->tot_len = htons(ip_len + udp_len - 1);
		break;
	case BAD_IP_VERSION:
		if (t->ipv6)
			((struct ipv6hdr *)ip)->version = 4;
		else
			((struct iphdr *)ip)->version = 6;
		break;
	case BAD_IHL:
		((struct iphdr *)ip)->ihl = 4;
		break;
	case BAD_TRANSPORT_OFFSET:
		meta->request.csum_start += 4;
		break;
	case TOO_MANY_SEGMENTS:
		meta->request.gso_size = 1;
		break;
	case IP_TUNNEL:
		((struct iphdr *)ip)->protocol = IPPROTO_IPIP;
		break;
	default:
		break;
	}
	return start + udp_len;
}

/* EAGAIN means no Tx progress until completions free resources, so return
 * to the caller to reap them instead of sleeping.
 */
static bool kick_tx(struct xsk *xsk)
{
	if (sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0 && errno != EAGAIN) {
		ksft_print_msg("sendto: %s\n", strerror(errno));
		return false;
	}
	return true;
}

static bool transmit(struct xsk *xsk, unsigned char *packet, unsigned int len,
		     const struct test_case *t, struct xsk_tx_metadata *meta)
{
	uint32_t index;
	uint64_t deadline = now_ms() + TIMEOUT_MS;
	uint64_t addrs[RING_SIZE];
	unsigned int copied = 0, n = 0, completed = 0;
	bool seen[RING_SIZE] = {};

	while (copied < len) {
		struct xdp_desc *desc;
		unsigned int amount = len - copied;
		uint64_t addr = n * FRAME_SIZE + META_LEN;

		if (amount > FRAME_SIZE - META_LEN)
			amount = FRAME_SIZE - META_LEN;
		if (!n && t->first_len && amount > t->first_len)
			amount = t->first_len;
		if (!n && t->bad == SHORT_HEADER)
			amount = meta->request.csum_start + sizeof(struct udphdr) - 1;
		memcpy(xsk->umem + addr, packet + copied, amount);
		if (!n)
			memcpy(xsk->umem + addr - META_LEN, meta, META_LEN);
		if (xsk_ring_prod__reserve(&xsk->tx, 1, &index) != 1) {
			ksft_print_msg("functional Tx ring reservation failed\n");
			return false;
		}
		desc = xsk_ring_prod__tx_desc(&xsk->tx, index);
		*desc = (struct xdp_desc) {
			.addr = addr,
			.len = amount,
			.options = (!n && meta->flags ? XDP_TX_METADATA : 0) |
				   (copied + amount < len ? XDP_PKT_CONTD : 0),
		};
		addrs[n++] = addr;
		copied += amount;
	}
	xsk_ring_prod__submit(&xsk->tx, n);
	while (completed < n) {
		unsigned int count, i;

		if (!kick_tx(xsk))
			return false;
		count = xsk_ring_cons__peek(&xsk->cq, RING_SIZE, &index);
		for (i = 0; i < count; i++) {
			uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->cq, index + i);
			unsigned int j;

			for (j = 0; j < n; j++)
				if (addr == addrs[j])
					break;
			if (j == n || seen[j]) {
				ksft_print_msg("functional Tx: invalid or duplicate completion\n");
				return false;
			}
			seen[j] = true;
		}
		xsk_ring_cons__release(&xsk->cq, count);
		completed += count;
		if (completed < n && now_ms() > deadline) {
			ksft_print_msg("completion timeout\n");
			return false;
		}
	}
	return true;
}

static bool valid_request(const struct test_case *t)
{
	return t->bad == VALID ||
	       (t->bad == LAUNCH_TIME && META_LEN >= 24 && !zero_copy);
}

static bool receive_packets(int fd, const struct test_case *t, unsigned int id)
{
	unsigned int count = 0, received = 0;
	unsigned int expected = valid_request(t) ? t->payload : 0;
	unsigned int expected_count = 0;
	uint64_t deadline;
	unsigned char packet[8192];

	if (valid_request(t)) {
		expected_count = (expected + 1399) / 1400;
		if (t->checksum_only || !expected)
			expected_count = 1;
	}
	deadline = now_ms() + (expected_count ? TIMEOUT_MS : 200);
	while (now_ms() < deadline) {
		unsigned int ip_len = t->ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
		unsigned int start = sizeof(struct ethhdr) + ip_len;
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		struct ethhdr *eth = (void *)packet;
		struct udphdr *uh = (void *)(packet + start);
		unsigned int payload, frame_len, max_frame_len, i;
		ssize_t len;

		if (poll(&pfd, 1, 20) < 0)
			return false;
		len = recv(fd, packet, sizeof(packet), MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EAGAIN)
				continue;
			return false;
		}
		if ((size_t)len < start + sizeof(*uh) ||
		    memcmp(eth->h_source, tx_mac, ETH_ALEN) ||
		    memcmp(eth->h_dest, rx_mac, ETH_ALEN) ||
		    eth->h_proto != htons(t->ipv6 ? ETH_P_IPV6 : ETH_P_IP) ||
		    uh->source != htons(TEST_PORT) || uh->dest != htons(TEST_PORT))
			continue;
		if (count >= expected_count)
			return false;
		payload = expected - received;
		if (!t->checksum_only && payload > 1400)
			payload = 1400;
		frame_len = start + sizeof(*uh) + payload;
		max_frame_len = frame_len < ETH_ZLEN ? ETH_ZLEN : frame_len;
		if (ntohs(uh->len) != sizeof(*uh) + payload ||
		    (size_t)len < frame_len || (size_t)len > max_frame_len ||
		    !uh->check ||
		    fold(sum_bytes(uh, sizeof(*uh) + payload) +
			 pseudo_sum(packet + sizeof(*eth), t->ipv6,
				    sizeof(*uh) + payload)) != 0xffff)
			return false;
		if (t->ipv6) {
			struct ipv6hdr *h = (void *)(packet + sizeof(*eth));

			if (ntohs(h->payload_len) != sizeof(*uh) + payload)
				return false;
		} else {
			struct iphdr *h = (void *)(packet + sizeof(*eth));

			if (ntohs(h->tot_len) != ip_len + sizeof(*uh) + payload ||
			    fold(sum_bytes(h, ip_len)) != 0xffff)
				return false;
		}
		for (i = 0; i < payload; i++)
			if (packet[start + sizeof(*uh) + i] !=
			    (received + i + id * 13) % 251)
				return false;
		received += payload;
		count++;
		if (count == expected_count)
			deadline = now_ms() + 100;
	}
	if (received != expected || count != expected_count) {
		ksft_print_msg("receive: %u/%u packets, %u/%u payload bytes\n",
			       count, expected_count, received, expected);
		return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	const char *tx_name = NULL, *rx_name = NULL;
	struct sockaddr_ll addr = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL) };
	struct xsk_tx_metadata meta;
	unsigned char packet[8192];
	struct xsk xsk;
	int fd, opt;
	bool loopback = false;
	unsigned int i;

	while ((opt = getopt(argc, argv, "i:r:zlC")) != -1) {
		if (opt == 'i')
			tx_name = optarg;
		else if (opt == 'r')
			rx_name = optarg;
		else if (opt == 'z')
			zero_copy = true;
		else if (opt == 'l')
			loopback = true;
		else if (opt == 'C')
			checksum_tests = true;
		else
			ksft_exit_fail_msg("Usage: %s [-z] [-l] [-C] -i TX_IFACE [-r RX_IFACE]\n",
					   argv[0]);
	}
	if (loopback) {
		if (rx_name && (!tx_name || strcmp(tx_name, rx_name)))
			ksft_exit_fail_msg("Loopback needs one interface for Tx and Rx\n");
		rx_name = tx_name;
	}
	ksft_print_header();
	ksft_set_plan(ARRAY_SIZE(cases));
	if (!tx_name || !rx_name || geteuid()) {
		for (i = 0; i < ARRAY_SIZE(cases); i++)
			ksft_test_result_skip("%s: needs root and -i TX_IFACE -r RX_IFACE\n",
					      cases[i].name);
		ksft_finished();
	}
	addr.sll_ifindex = if_nametoindex(rx_name);
	if (!addr.sll_ifindex || !if_nametoindex(tx_name) ||
	    (!loopback && !strcmp(tx_name, rx_name)))
		ksft_exit_fail_msg("Use two connected interfaces, or -l\n");
	get_mac(tx_name, tx_mac);
	get_mac(rx_name, rx_mac);
	if (loopback) {
		/* Avoid sending the port's own source MAC back into its Rx filter. */
		tx_mac[0] = (tx_mac[0] | 2) & ~1;
		tx_mac[ETH_ALEN - 1] ^= 0x80;
		memset(rx_mac, 0xff, ETH_ALEN);
	}
	{
		struct ifreq ifr = {};
		int ctl = socket(AF_INET, SOCK_DGRAM, 0);

		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", tx_name);
		if (ctl < 0 || ioctl(ctl, SIOCGIFMTU, &ifr) || ifr.ifr_mtu != 1500)
			ksft_exit_fail_msg("Transmitting interface must have MTU 1500\n");
		close(ctl);
	}
	fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
	if (fd < 0)
		ksft_exit_fail_msg("packet socket: %s\n", strerror(errno));
	{
		int ignore_outgoing = 1;

		if (setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING,
			       &ignore_outgoing, sizeof(ignore_outgoing)) ||
		    bind(fd, (void *)&addr, sizeof(addr)))
			ksft_exit_fail_msg("packet socket setup: %s\n", strerror(errno));
	}
	open_xsk(&xsk, if_nametoindex(tx_name), false);
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const struct test_case *t = &cases[i];
		struct xdp_statistics before, after;
		socklen_t size = sizeof(before);
		unsigned int len, expected_invalid = 0;
		bool ok;

		if (!checksum_tests && t->checksum_only) {
			ksft_test_result_skip("%s: checksum offload cases need -C\n",
					      t->name);
			continue;
		}
		if (zero_copy && t->bad == SW_CHECKSUM) {
			ksft_test_result_skip("%s: software checksum is copy mode only\n",
					      t->name);
			continue;
		}
		if (!zero_copy && t->checksum_only && t->bad != VALID) {
			ksft_test_result_skip("%s: copy mode fails sendmsg() instead\n",
					      t->name);
			continue;
		}
		if (t->bad == SW_CHECKSUM) {
			close_xsk(&xsk);
			open_xsk(&xsk, if_nametoindex(tx_name), true);
		} else if (!zero_copy && i && cases[i - 1].bad == SW_CHECKSUM) {
			close_xsk(&xsk);
			open_xsk(&xsk, if_nametoindex(tx_name), false);
		}
		if (getsockopt(xsk.fd, SOL_XDP, XDP_STATISTICS, &before, &size))
			ksft_exit_fail_msg("XDP_STATISTICS: %s\n", strerror(errno));
		len = make_packet(packet, t, i, &meta);
		ok = transmit(&xsk, packet, len, t, &meta);
		if (!ok)
			ksft_exit_fail_msg("%s: submission/completion failed\n", t->name);
		ok = receive_packets(fd, t, i);
		if (!valid_request(t))
			expected_invalid = t->first_len || t->bad == SHORT_HEADER ? 2 : 1;
		size = sizeof(after);
		if (getsockopt(xsk.fd, SOL_XDP, XDP_STATISTICS, &after, &size))
			ksft_exit_fail_msg("XDP_STATISTICS: %s\n", strerror(errno));
		ok &= after.tx_invalid_descs - before.tx_invalid_descs == expected_invalid;
		ksft_test_result(ok, "%s\n", t->name);
	}
	close_xsk(&xsk);
	close(fd);
	ksft_finished();
}
