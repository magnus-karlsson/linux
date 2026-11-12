// SPDX-License-Identifier: GPL-2.0
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
#include "xsk.h"

#ifndef RING_SIZE
#define RING_SIZE 1024
#endif
#ifndef NUM_FRAMES
#define NUM_FRAMES 1024
#endif
#define FRAME_SIZE 4096
/* An in-flight frame can charge slightly more than two pages of skb truesize.
 * The kernel doubles the requested value, which leaves room for all frames.
 */
#define SNDBUF_SIZE (NUM_FRAMES * FRAME_SIZE * 2)
#ifndef META_LEN
#define META_LEN 16
#endif
#define TEST_PORT 49732
#define TIMEOUT_MS 2000
#define BUSY_POLL_USECS 20
#define BUSY_POLL_BUDGET 64
#define LOAD_PAYLOAD 6000
#define LOAD_GSO_SIZE 1472
#define LOAD_DATAGRAMS ((LOAD_PAYLOAD + 1399) / 1400)
#define MAX_UDP_PAYLOAD 65507
#define MAX_PACKET_SIZE (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + \
			 MAX_UDP_PAYLOAD)

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
static bool no_busy_poll;
static bool checksum_tests;
static unsigned int load_payload = LOAD_PAYLOAD;
static bool no_payload_copy;

static uint64_t tx_drops(const char *name)
{
	char path[128];
	unsigned long long drops;
	FILE *file;

	snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_dropped", name);
	file = fopen(path, "r");
	if (!file)
		ksft_exit_fail_msg("open %s: %s\n", path, strerror(errno));
	if (fscanf(file, "%llu", &drops) != 1)
		ksft_exit_fail_msg("read %s failed\n", path);
	fclose(file);
	return drops;
}

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

static void set_xsk_option(int fd, int option, const void *value,
			   socklen_t len, const char *name)
{
	if (setsockopt(fd, SOL_XDP, option, value, len))
		ksft_exit_fail_msg("%s: %s\n", name, strerror(errno));
}

static void enable_busy_poll(int fd)
{
	const struct {
		int option;
		int value;
		const char *name;
	} options[] = {
		{ SO_PREFER_BUSY_POLL, 1, "SO_PREFER_BUSY_POLL" },
		{ SO_BUSY_POLL, BUSY_POLL_USECS, "SO_BUSY_POLL" },
		{ SO_BUSY_POLL_BUDGET, BUSY_POLL_BUDGET, "SO_BUSY_POLL_BUDGET" },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(options); i++)
		if (setsockopt(fd, SOL_SOCKET, options[i].option, &options[i].value,
			       sizeof(options[i].value)))
			ksft_exit_fail_msg("%s: %s\n", options[i].name, strerror(errno));
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
	unsigned int budget = RING_SIZE;
	int sndbuf = SNDBUF_SIZE;
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

		while ((err = xsk_socket__create(&xsk->socket, ifindex, 0, xsk->umem_handle,
						NULL, &xsk->tx, &config))) {
			if (err != -EBUSY || now_ms() >= deadline)
				ksft_exit_fail_msg("socket creation: %s\n", strerror(-err));
			usleep(10000);
		}
		xsk->fd = xsk_socket__fd(xsk->socket);
		set_xsk_option(xsk->fd, XDP_MAX_TX_SKB_BUDGET, &budget, sizeof(budget),
			       "XDP_MAX_TX_SKB_BUDGET");
	}
	/* Copy mode charges each skb's truesize, up to twice its data, to the
	 * send buffer. Size it so that the Tx ring, not sk_sndbuf, limits the
	 * number of packets in flight, as in zero-copy mode.
	 */
	if (setsockopt(xsk->fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)))
		ksft_exit_fail_msg("SO_SNDBUFFORCE: %s\n", strerror(errno));
	if (!no_busy_poll)
		enable_busy_poll(xsk->fd);
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

static bool kick_tx(struct xsk *xsk)
{
	while (sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
		if (errno != EAGAIN) {
			ksft_print_msg("sendto: %s\n", strerror(errno));
			return false;
		}
		usleep(1000);
	}
	return true;
}

/* EAGAIN means no Tx progress until completions free resources, so return
 * to the caller to reap them instead of sleeping.
 */
static bool kick_tx_once(struct xsk *xsk)
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

enum load_mode {
	LOAD_USO,
	LOAD_SOFTWARE,
	LOAD_HW_CHECKSUM,
};

static unsigned int make_load_datagram(unsigned char *datagram,
				      const unsigned char *packet, unsigned int segment,
				      bool hw_checksum, unsigned int total_payload,
				      unsigned int gso_size, bool copy_payload)
{
	const unsigned int udp_offset = ETH_HLEN + sizeof(struct iphdr);
	const unsigned int header_len = udp_offset + sizeof(struct udphdr);
	unsigned int offset = segment * gso_size;
	unsigned int payload = total_payload - offset;
	struct iphdr ip;
	struct udphdr udp;

	if (payload > gso_size)
		payload = gso_size;
	memcpy(datagram, packet, header_len);
	if (copy_payload)
		memcpy(datagram + header_len, packet + header_len + offset, payload);
	memcpy(&ip, packet + ETH_HLEN, sizeof(ip));
	ip.tot_len = htons(sizeof(ip) + sizeof(udp) + payload);
	ip.id = htons(ntohs(ip.id) + segment);
	ip.check = 0;
	ip.check = htons((uint16_t)~fold(sum_bytes(&ip, sizeof(ip))));
	memcpy(datagram + ETH_HLEN, &ip, sizeof(ip));
	memcpy(&udp, packet + udp_offset, sizeof(udp));
	udp.len = htons(sizeof(udp) + payload);
	udp.check = 0;
	memcpy(datagram + udp_offset, &udp, sizeof(udp));
	if (hw_checksum) {
		udp.check = htons(fold(pseudo_sum(&ip, false, sizeof(udp) + payload)));
	} else {
		udp.check = htons((uint16_t)~fold(sum_bytes(datagram + udp_offset,
							 sizeof(udp) + payload) +
					       pseudo_sum(&ip, false, sizeof(udp) + payload)));
		if (!udp.check)
			udp.check = htons(0xffff);
	}
	memcpy(datagram + udp_offset, &udp, sizeof(udp));
	return header_len + payload;
}

static bool check_userspace_segmentation(struct xsk *xsk, int rx_fd, bool hw_checksum)
{
	const struct test_case test = { .payload = LOAD_PAYLOAD };
	struct xsk_tx_metadata meta;
	unsigned char packet[8192], datagram[FRAME_SIZE];
	unsigned int i;

	make_packet(packet, &test, ARRAY_SIZE(cases), &meta);
	meta.flags = hw_checksum ? XDP_TXMD_FLAGS_CHECKSUM : 0;
	meta.request.gso_size = 0;
	for (i = 0; i < LOAD_DATAGRAMS; i++) {
		unsigned int len = make_load_datagram(datagram, packet, i, hw_checksum,
						      LOAD_PAYLOAD, 1400, true);

		if (!transmit(xsk, datagram, len, &test, &meta))
			ksft_exit_fail_msg("userspace segmentation: submission/completion failed\n");
	}
	return receive_packets(rx_fd, &test, ARRAY_SIZE(cases));
}

static bool sustained_load(struct xsk *xsk, unsigned int seconds,
			   const char *tx_name, enum load_mode mode)
{
	bool uso = mode == LOAD_USO, hw_checksum = mode == LOAD_HW_CHECKSUM;
	const char *name = uso ? "USO + HW checksum" :
			   hw_checksum ? "userspace segmentation + HW checksum" :
					 "userspace segmentation (no offloads)";
	const struct test_case test = {
		.payload = load_payload,
	};
	struct xdp_statistics before, after;
	struct xsk_tx_metadata meta;
	unsigned char packet[MAX_PACKET_SIZE];
	unsigned int datagrams = (load_payload + LOAD_GSO_SIZE - 1) / LOAD_GSO_SIZE;
	unsigned int packet_len = ETH_HLEN + sizeof(struct iphdr) +
				  sizeof(struct udphdr) + load_payload;
	unsigned int batch_descs = uso ? (packet_len + FRAME_SIZE - META_LEN - 1) /
					(FRAME_SIZE - META_LEN) : datagrams;
	bool busy[NUM_FRAMES] = {};
	unsigned int frame_count = no_payload_copy ?
				   NUM_FRAMES / batch_descs * batch_descs : NUM_FRAMES;
	uint32_t free_frames[NUM_FRAMES], heads[NUM_FRAMES], available = frame_count;
	uint64_t submitted = 0, completed = 0, start, end, stop;
	uint64_t drops = tx_drops(tx_name);
	unsigned int len, i;
	socklen_t stat_len = sizeof(before);
	bool ok = true;

	if (getsockopt(xsk->fd, SOL_XDP, XDP_STATISTICS, &before, &stat_len))
		ksft_exit_fail_msg("load XDP_STATISTICS: %s\n", strerror(errno));
	len = make_packet(packet, &test, 0, &meta);
	if (hw_checksum)
		meta.flags = XDP_TXMD_FLAGS_CHECKSUM;
	meta.request.gso_size = uso ? LOAD_GSO_SIZE : 0;
	memset(heads, 0xff, sizeof(heads));
	for (i = 0; i < frame_count; i++) {
		unsigned int role = i % batch_descs;
		unsigned char *data = xsk->umem + i * FRAME_SIZE + META_LEN;

		free_frames[i] = i;
		if (uso || hw_checksum)
			memcpy(xsk->umem + i * FRAME_SIZE, &meta, META_LEN);
		if (!no_payload_copy)
			continue;
		/* Keep each frame's payload position fixed across completions. */
		free_frames[i] = heads[role];
		heads[role] = i;
		if (uso) {
			unsigned int offset = role * (FRAME_SIZE - META_LEN);
			unsigned int amount = len - offset;

			if (amount > FRAME_SIZE - META_LEN)
				amount = FRAME_SIZE - META_LEN;
			memcpy(data, packet + offset, amount);
		} else {
			make_load_datagram(data, packet, role, hw_checksum, load_payload,
					   LOAD_GSO_SIZE, true);
		}
	}
	start = now_ms();
	stop = start + (uint64_t)seconds * 1000;
	for (;;) {
		uint32_t cq_index, tx_index, count, c, queued = 0;
		uint64_t now = now_ms();

		count = xsk_ring_cons__peek(&xsk->cq, RING_SIZE, &cq_index);
		for (c = 0; c < count; c++) {
			uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->cq, cq_index + c);
			uint64_t frame = addr / FRAME_SIZE;

			if (frame >= NUM_FRAMES || addr % FRAME_SIZE != META_LEN ||
			    !busy[frame] || available == frame_count) {
				ksft_print_msg("load: invalid or duplicate completion address %llu\n",
					       (unsigned long long)addr);
				return false;
			}
			busy[frame] = false;
			if (no_payload_copy) {
				unsigned int role = frame % batch_descs;

				free_frames[frame] = heads[role];
				heads[role] = frame;
				available++;
			} else {
				free_frames[available++] = frame;
			}
			completed++;
		}
		xsk_ring_cons__release(&xsk->cq, count);
		if (now >= stop)
			break;
		while (now < stop && available >= batch_descs) {
			if (no_payload_copy) {
				for (i = 0; i < batch_descs; i++)
					if (heads[i] == UINT32_MAX)
						break;
				if (i != batch_descs)
					break;
			}
			if (xsk_ring_prod__reserve(&xsk->tx, batch_descs, &tx_index) != batch_descs)
				break;
			for (i = 0; i < batch_descs; i++) {
				uint32_t frame;
				uint64_t addr;
				uint32_t amount;

				if (no_payload_copy) {
					frame = heads[i];
					heads[i] = free_frames[frame];
					available--;
				} else {
					frame = free_frames[--available];
				}
				addr = frame * FRAME_SIZE + META_LEN;
				busy[frame] = true;
				if (uso) {
					uint32_t offset = i * (FRAME_SIZE - META_LEN);

					amount = len - offset;
					if (amount > FRAME_SIZE - META_LEN)
						amount = FRAME_SIZE - META_LEN;
					if (!no_payload_copy)
						memcpy(xsk->umem + addr, packet + offset, amount);
					else if (!i)
						memcpy(xsk->umem + addr, packet, ETH_HLEN +
						       sizeof(struct iphdr) + sizeof(struct udphdr));
				} else {
					amount = make_load_datagram(xsk->umem + addr, packet, i,
								    hw_checksum, load_payload,
								    LOAD_GSO_SIZE, !no_payload_copy);
				}
				*xsk_ring_prod__tx_desc(&xsk->tx, tx_index + i) = (struct xdp_desc) {
					.addr = addr,
					.len = amount,
					.options = uso ? ((!i ? XDP_TX_METADATA : 0) |
							 (i + 1 < batch_descs ? XDP_PKT_CONTD : 0)) :
							 (hw_checksum ? XDP_TX_METADATA : 0),
				};
				submitted++;
			}
			queued += batch_descs;
			now = now_ms();
		}
		xsk_ring_prod__submit(&xsk->tx, queued);
		if (now >= stop)
			break;
		if (!kick_tx_once(xsk)) {
			ok = false;
			break;
		}
	}
	end = now_ms();
	stat_len = sizeof(after);
	if (getsockopt(xsk->fd, SOL_XDP, XDP_STATISTICS, &after, &stat_len))
		ksft_exit_fail_msg("load XDP_STATISTICS: %s\n", strerror(errno));
	ksft_print_msg("Load stopped: %llu submitted, %llu completed, %llu outstanding descriptors\n",
		       (unsigned long long)submitted, (unsigned long long)completed,
		       (unsigned long long)(submitted - completed));
	ok &= completed >= RING_SIZE * 2 &&
	      after.tx_invalid_descs == before.tx_invalid_descs &&
	      tx_drops(tx_name) == drops;
	if (!ok)
		ksft_print_msg("load: submitted=%llu completed=%llu invalid=%llu drops=%llu\n",
			       (unsigned long long)submitted,
			       (unsigned long long)completed,
			       (unsigned long long)(after.tx_invalid_descs -
						    before.tx_invalid_descs),
			       (unsigned long long)(tx_drops(tx_name) - drops));
	ksft_print_msg("Sustained %s %s: %.3f s, %llu completed batches (%u UDP datagrams/batch)\n",
		       zero_copy ? "zero-copy" : "copy", name,
		       (end - start) / 1000.0,
		       (unsigned long long)(completed / batch_descs), datagrams);
	ksft_print_msg("Tx-completion-derived throughput: %.0f batches/s, %.0f Tx requests/s, %.0f UDP packets/s (not verified Rx throughput)\n",
		       (completed / batch_descs) * 1000.0 / (end - start ?: 1),
		       (completed / batch_descs) * (uso ? 1 : datagrams) *
		       1000.0 / (end - start ?: 1),
		       (completed / batch_descs) * datagrams * 1000.0 /
		       (end - start ?: 1));
	ksft_print_msg("LOAD_RESULT,%s,%s,%u,%u,%llu,%llu,%u,%s\n",
		       zero_copy ? "zero-copy" : "copy",
		       uso ? "uso" : hw_checksum ? "hw-checksum" : "software",
		       load_payload, LOAD_GSO_SIZE, (unsigned long long)(end - start),
		       (unsigned long long)(completed / batch_descs), datagrams,
		       ok ? "pass" : "fail");
	return ok;
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
	bool sustained_only = false;
	bool uso_only = false, no_capture = false;
	unsigned int duration = 5;
	unsigned int i;

	while ((opt = getopt(argc, argv, "i:r:zlsunPBCd:p:")) != -1) {
		if (opt == 'i')
			tx_name = optarg;
		else if (opt == 'r')
			rx_name = optarg;
		else if (opt == 'z')
			zero_copy = true;
		else if (opt == 'l')
			loopback = true;
		else if (opt == 's')
			sustained_only = true;
		else if (opt == 'u') {
			uso_only = true;
			sustained_only = true;
		} else if (opt == 'n')
			no_capture = true;
		else if (opt == 'P')
			no_payload_copy = true;
		else if (opt == 'B')
			no_busy_poll = true;
		else if (opt == 'C')
			checksum_tests = true;
		else if (opt == 'd' || opt == 'p') {
			char *end;
			unsigned long value;

			errno = 0;
			value = strtoul(optarg, &end, 10);
			if (errno || !*optarg || *end ||
			    (opt == 'd' ? value > 60 : !value || value > MAX_UDP_PAYLOAD))
				ksft_exit_fail_msg("Duration must be 0..60; payload must be 1..65507 bytes\n");
			if (opt == 'd')
				duration = value;
			else
				load_payload = value;
		} else
			ksft_exit_fail_msg("Usage: %s [-z] [-l] [-s|-u] [-n] [-P] [-B] [-C] [-d SECONDS] [-p PAYLOAD_BYTES] -i TX_IFACE [-r RX_IFACE]\n",
					   argv[0]);
	}
	if (loopback) {
		if (rx_name && (!tx_name || strcmp(tx_name, rx_name)))
			ksft_exit_fail_msg("Loopback requires the same transmitting and receiving interface\n");
		rx_name = tx_name;
	}
	ksft_print_header();
	ksft_set_plan(sustained_only ? 3 : 6 + ARRAY_SIZE(cases));
	if (!sustained_only) {
		ksft_test_result(sizeof(struct xsk_tx_metadata) == 24 &&
				 offsetof(struct xsk_tx_metadata, request.gso_size) == 12 &&
				 offsetof(struct xsk_tx_metadata, request.network_offset) == 14 &&
				 offsetof(struct xsk_tx_metadata, request.launch_time) == 16 &&
				 offsetof(struct xsk_tx_metadata, completion.tx_timestamp) == 8,
				 "metadata ABI size and offsets\n");
	}
	if (!tx_name || !rx_name || geteuid()) {
		if (!sustained_only) {
			for (i = 0; i < ARRAY_SIZE(cases); i++)
				ksft_test_result_skip("%s: needs root and -i TX_IFACE -r RX_IFACE\n",
						      cases[i].name);
			ksft_test_result_skip("userspace segmentation: needs root and interfaces\n");
			ksft_test_result_skip("userspace segmentation + HW checksum: needs root and interfaces\n");
		}
		ksft_test_result_skip("sustained load: needs root and interfaces\n");
		ksft_test_result_skip("sustained userspace segmentation: needs root and interfaces\n");
		ksft_test_result_skip("sustained HW checksum only: needs root and interfaces\n");
		ksft_finished();
	}
	addr.sll_ifindex = if_nametoindex(rx_name);
	if (!addr.sll_ifindex || !if_nametoindex(tx_name) ||
	    (!loopback && !strcmp(tx_name, rx_name)))
		ksft_exit_fail_msg("Specify distinct, connected interfaces, or use -l for loopback\n");
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
	if (sustained_only)
		goto load;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const struct test_case *t = &cases[i];
		struct xdp_statistics before, after;
		socklen_t size = sizeof(before);
		unsigned int len, expected_invalid = 0;
		bool ok;

		if (!checksum_tests && t->checksum_only) {
			ksft_test_result_skip("%s: standalone checksum offload disabled by default\n",
					      t->name);
			continue;
		}
		if (zero_copy && t->bad == SW_CHECKSUM) {
			ksft_test_result_skip("%s: not supported by ice zero-copy\n", t->name);
			continue;
		}
		if (!zero_copy && t->checksum_only && t->bad != VALID) {
			ksft_test_result_skip("%s: copy mode returns non-USO metadata errors from sendmsg()\n",
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
	ksft_test_result(check_userspace_segmentation(&xsk, fd, false),
			 "userspace segmentation packet contents (no offloads)\n");
	if (!checksum_tests)
		ksft_test_result_skip("userspace segmentation + HW checksum only: standalone checksum offload disabled by default\n");
	else
		ksft_test_result(check_userspace_segmentation(&xsk, fd, true),
				 "userspace segmentation packet contents (HW checksum only)\n");
load:
	if (duration) {
		struct ifreq ifr = {};
		int ctl = socket(AF_INET, SOCK_DGRAM, 0);

		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", rx_name);
		if (ctl < 0 || ioctl(ctl, SIOCGIFFLAGS, &ifr))
			ksft_exit_fail_msg("Receiving interface flags: %s\n", strerror(errno));
		close(ctl);
		if (ifr.ifr_flags & IFF_PROMISC)
			ksft_exit_fail_msg("Disable promiscuous mode on the receiving interface for load testing\n");
		get_mac(rx_name, rx_mac);
		rx_mac[0] = (rx_mac[0] | 2) & ~1;
		rx_mac[ETH_ALEN - 1] ^= 0x40;
		ksft_print_msg("Load destination: %02x:%02x:%02x:%02x:%02x:%02x (unregistered unicast; NIC Rx filtering)\n",
			       rx_mac[0], rx_mac[1], rx_mac[2], rx_mac[3], rx_mac[4], rx_mac[5]);
	}
	if (no_capture) {
		close(fd);
		fd = -1;
	}
	ksft_print_msg("Load setup: Tx/CQ=%u entries, %u frames, %u bytes/frame, %u UMEM bytes, capture=%s\n",
		       RING_SIZE, NUM_FRAMES, FRAME_SIZE, NUM_FRAMES * FRAME_SIZE,
		       no_capture ? "off" : "on");
	ksft_print_msg("Send buffer: SO_SNDBUFFORCE %u bytes; EAGAIN retried without sleeping\n",
		       SNDBUF_SIZE);
	if (no_busy_poll)
		ksft_print_msg("Preferred busy poll: disabled\n");
	else
		ksft_print_msg("Preferred busy poll: enabled, %u usecs, budget=%u; driven by nonblocking sendto\n",
			       BUSY_POLL_USECS, BUSY_POLL_BUDGET);
	ksft_print_msg("Payload copying: %s; packet headers refreshed on every submission\n",
		       no_payload_copy ? "once before timing" : "every submission");
	if (duration) {
		if (zero_copy &&
		    load_payload + 42 > 8 * (FRAME_SIZE - META_LEN)) {
			ksft_test_result_skip("sustained USO: payload exceeds ice's eight-buffer limit\n");
			ksft_print_msg("LOAD_RESULT,zero-copy,uso,%u,%u,0,0,%u,skip\n",
				       load_payload, LOAD_GSO_SIZE,
				       (load_payload + LOAD_GSO_SIZE - 1) / LOAD_GSO_SIZE);
		} else {
			ksft_test_result(sustained_load(&xsk, duration, tx_name, LOAD_USO),
					 "sustained multi-buffer USO load\n");
		}
		if (uso_only) {
			ksft_test_result_skip("userspace segmentation disabled with -u\n");
			ksft_test_result_skip("HW checksum only disabled with -u\n");
			goto done;
		}
		close_xsk(&xsk);
		open_xsk(&xsk, if_nametoindex(tx_name), false);
		ksft_test_result(sustained_load(&xsk, duration, tx_name, LOAD_SOFTWARE),
				 "sustained userspace segmentation load (no offloads)\n");
		if (!checksum_tests) {
			ksft_test_result_skip("sustained HW checksum only disabled by default\n");
		} else {
			close_xsk(&xsk);
			open_xsk(&xsk, if_nametoindex(tx_name), false);
			ksft_test_result(sustained_load(&xsk, duration, tx_name,
							LOAD_HW_CHECKSUM),
					 "sustained userspace segmentation load (HW checksum only)\n");
		}
	} else {
		ksft_test_result_skip("sustained load disabled with -d 0\n");
		ksft_test_result_skip("sustained userspace segmentation disabled with -d 0\n");
		ksft_test_result_skip("sustained HW checksum only disabled with -d 0\n");
	}
done:
	close_xsk(&xsk);
	if (fd >= 0)
		close(fd);
	ksft_finished();
}
