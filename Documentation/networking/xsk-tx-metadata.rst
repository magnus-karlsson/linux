.. SPDX-License-Identifier: GPL-2.0

==================
AF_XDP TX Metadata
==================

This document describes how to enable offloads when transmitting packets
via :doc:`af_xdp`. Refer to :doc:`xdp-rx-metadata` on how to access similar
metadata on the receive side.

General Design
==============

The headroom for the metadata is reserved via ``tx_metadata_len`` and
``XDP_UMEM_TX_METADATA_LEN`` flag in ``struct xdp_umem_reg``. The metadata
length is therefore the same for every socket that shares the same umem.
The metadata layout is a fixed UAPI, refer to ``struct xsk_tx_metadata`` in
``include/uapi/linux/if_xdp.h``. Thus, generally, the ``tx_metadata_len``
field above should contain ``sizeof(struct xsk_tx_metadata)``.

Note that in the original implementation the ``XDP_UMEM_TX_METADATA_LEN``
flag was not required. Applications might attempt to create a umem
with a flag first and if it fails, do another attempt without a flag.

The headroom and the metadata itself should be located right before
``xdp_desc->addr`` in the umem frame. Within a frame, the metadata
layout is as follows::

           tx_metadata_len
     /                         \
    +-----------------+---------+----------------------------+
    | xsk_tx_metadata | padding |          payload           |
    +-----------------+---------+----------------------------+
                                ^
                                |
                          xdp_desc->addr

An AF_XDP application can request headrooms larger than ``sizeof(struct
xsk_tx_metadata)``. The kernel will ignore the padding (and will still
use ``xdp_desc->addr - tx_metadata_len`` to locate
the ``xsk_tx_metadata``). For the frames that shouldn't carry
any metadata (i.e., the ones that don't have ``XDP_TX_METADATA`` option),
the metadata area is ignored by the kernel as well.

The flags field enables the particular offload:

- ``XDP_TXMD_FLAGS_TIMESTAMP``: requests the device to put transmission
  timestamp into ``completion.tx_timestamp`` field of
  ``struct xsk_tx_metadata``.
- ``XDP_TXMD_FLAGS_CHECKSUM``: requests the device to calculate L4
  checksum. ``request.csum_start`` specifies byte offset of where the
  checksumming should start and ``request.csum_offset`` specifies byte offset
  where the device should store the computed checksum.
- ``XDP_TXMD_FLAGS_LAUNCH_TIME``: requests the device to schedule the
  packet for transmission at a pre-determined time called launch time. The
  value of launch time is indicated by ``request.launch_time`` field of
  ``struct xsk_tx_metadata``.
- ``XDP_TXMD_FLAGS_USO``: requests UDP segmentation offload.
  ``request.gso_size`` specifies UDP payload bytes per output datagram;
  ``request.network_offset`` identifies the IP header.

Besides the flags above, in order to trigger the offloads, the first
packet's ``struct xdp_desc`` descriptor should set ``XDP_TX_METADATA``
bit in the ``options`` field. Also note that in a multi-buffer packet
only the first chunk should carry the metadata.

Software TX Checksum
====================

For development and testing purposes it's possible to pass
``XDP_UMEM_TX_SW_CSUM`` flag to ``XDP_UMEM_REG`` UMEM registration call.
In this case, when running in ``XDP_COPY`` mode, the TX checksum
is calculated on the CPU. Do not enable this option in production because
it will negatively affect performance.

UDP Segmentation
================

To request UDP segmentation offload (USO), bind the socket in
``XDP_COPY`` mode and set ``XDP_TXMD_FLAGS_USO | XDP_TXMD_FLAGS_CHECKSUM``
in the Tx metadata. Reserve at least 16 bytes of metadata and set
``XDP_TX_METADATA`` on the first descriptor of the packet.

Submit an Ethernet frame containing one IP header, one UDP header, and the
aggregate UDP payload. Set ``request.network_offset`` to the IP header
offset, ``request.csum_start`` to the UDP header offset, and
``request.csum_offset`` to the UDP checksum field offset (6 bytes).
Header offsets are measured from the first descriptor's packet-data address,
excluding metadata. Set ``request.gso_size`` to the number of UDP payload
bytes per output datagram, excluding headers; the last datagram may be
shorter.

USO is only available on Ethernet devices. ``request.network_offset``
locates the IP header, and its version selects IPv4 or IPv6. In copy mode,
the EtherType, after up to ``VLAN_MAX_DEPTH`` (8) VLAN tags, must lead to
the same IP header, since drivers rely on it. IPv4 headers may carry
options but must not be fragmented. In IPv6, the UDP header must directly
follow the fixed header; extension headers are not supported.

The IP and UDP lengths must describe the aggregate packet. Initialize the
UDP checksum field with the partial pseudoheader checksum seed for that
packet. The device generates the per-datagram lengths and UDP checksums and,
for IPv4 segmentation, the IP header checksums. Supply a valid IPv4 header
checksum as well, since a request that fits in one datagram uses ordinary
checksum offload without segmentation.

All headers through UDP must be in the first buffer. Multi-buffer packets
use ``XDP_USE_SG`` and ``XDP_PKT_CONTD``, with metadata only on the first
descriptor. Each output IP packet must fit the device MTU, and requests
remain subject to the device's segmentation limits. Query
``tx-udp-segmentation`` through ethtool to check whether skb UDP segmentation
offload is enabled.

AF_XDP never segments the packet itself. In copy mode, a request is
rejected unless the bound device advertises UDP segmentation offload, and
the packet is passed to its driver unsegmented. As with ``UDP_SEGMENT``
sockets, how the segmentation is carried out is up to the driver, which
may build the per-datagram headers in software. Stacked devices such as
VLAN, bonding, or macvlan advertise UDP segmentation regardless of the
lower device and forward the packet through the lower device's qdisc,
where it is segmented in software if the lower device lacks the offload.

Some devices, such as those driven by mlx5 and atlantic, implement UDP
segmentation as a partial GSO feature that needs the stack to segment the
packet partially in software first. In copy mode, these devices reject
requests that produce more than one datagram, even though
``tx-udp-segmentation`` is reported as enabled.

A USO request that is rejected is dropped: its buffers are returned
through the completion ring and counted in the socket's ``tx_invalid_descs``
statistic. This is the only indication of the failure, whatever its cause:
invalid metadata or headers, the MTU, segmentation limits, or a device
without the offload. In copy mode, errors in other Tx metadata fail
``sendmsg()`` and leave the descriptor on the Tx ring.

USO cannot be combined with ``XDP_UMEM_TX_SW_CSUM`` or
``XDP_TXMD_FLAGS_TIMESTAMP``.

Launch Time
===========

The value of the requested launch time should be based on the device's PTP
Hardware Clock (PHC) to ensure accuracy. AF_XDP takes a different data path
compared to the ETF queuing discipline, which organizes packets and delays
their transmission. Instead, AF_XDP immediately hands off the packets to
the device driver without rearranging their order or holding them prior to
transmission. Since the driver maintains FIFO behavior and does not perform
packet reordering, a packet with a launch time request will block other
packets in the same Tx Queue until it is sent. Therefore, it is recommended
to allocate separate queue for scheduling traffic that is intended for
future transmission.

In scenarios where the launch time offload feature is disabled, the device
driver is expected to disregard the launch time request. For correct
interpretation and meaningful operation, the launch time should never be
set to a value larger than the farthest programmable time in the future
(the horizon). Different devices have different hardware limitations on the
launch time offload feature.

stmmac driver
-------------

For stmmac, TSO and launch time (TBS) features are mutually exclusive for
each individual Tx Queue. By default, the driver configures Tx Queue 0 to
support TSO and the rest of the Tx Queues to support TBS. The launch time
hardware offload feature can be enabled or disabled by using the tc-etf
command to call the driver's ndo_setup_tc() callback.

The value of the launch time that is programmed in the Enhanced Normal
Transmit Descriptors is a 32-bit value, where the most significant 8 bits
represent the time in seconds and the remaining 24 bits represent the time
in 256 ns increments. The programmed launch time is compared against the
PTP time (bits[39:8]) and rolls over after 256 seconds. Therefore, the
horizon of the launch time for dwmac4 and dwxlgmac2 is 128 seconds in the
future.

igc driver
----------

For igc, all four Tx Queues support the launch time feature. The launch
time hardware offload feature can be enabled or disabled by using the
tc-etf command to call the driver's ndo_setup_tc() callback. When entering
TSN mode, the igc driver will reset the device and create a default Qbv
schedule with a 1-second cycle time, with all Tx Queues open at all times.

The value of the launch time that is programmed in the Advanced Transmit
Context Descriptor is a relative offset to the starting time of the Qbv
transmission window of the queue. The First flag of the descriptor can be
set to schedule the packet for the next Qbv cycle. Therefore, the horizon
of the launch time for i225 and i226 is the ending time of the next cycle
of the Qbv transmission window of the queue. For example, when the Qbv
cycle time is set to 1 second, the horizon of the launch time ranges
from 1 second to 2 seconds, depending on where the Qbv cycle is currently
running.

USO with launch time
====================

Add ``XDP_TXMD_FLAGS_LAUNCH_TIME`` to the USO and checksum flags and set
``request.launch_time`` to schedule the segmented packet. This combination
requires at least 24 bytes of Tx metadata.

The launch time applies to the start of the segmented packet: the first
output UDP datagram is scheduled, and subsequent datagrams follow according
to the device's scheduling rules. This does not request per-datagram pacing
or separate launch times.

The skb path passes one unsegmented GSO skb and its launch time directly to
the bound device's driver, bypassing that device's qdisc, including ETF.
On stacked devices, the lower device's qdisc and software segmentation
may still apply, as described above. The driver and selected queue
must support UDP segmentation and launch time together. Separate support
for either offload does not establish support for their combination.
As with ordinary launch-time requests, drivers may ignore the time when
scheduling is disabled or unsupported. Acceptance or Tx completion alone
does not prove that a packet was transmitted at the requested time.

The clock, queue configuration, and scheduling horizon requirements above
also apply to USO launch-time requests.

Querying Device Capabilities
============================

Every device exports its offload capabilities via the Netlink netdev family.
Query the ``xsk-features`` attribute in
``Documentation/netlink/specs/netdev.yaml``. Its bits are defined by the
``xsk-flags`` enum.

- ``tx-timestamp``: device supports ``XDP_TXMD_FLAGS_TIMESTAMP``
- ``tx-checksum``: device supports ``XDP_TXMD_FLAGS_CHECKSUM``
- ``tx-launch-time-fifo``: device supports ``XDP_TXMD_FLAGS_LAUNCH_TIME``

See ``tools/net/ynl/samples/netdev.c`` on how to query this information.

Example
=======

See ``tools/testing/selftests/bpf/xdp_hw_metadata.c`` for an example
program that handles TX metadata. Also see https://github.com/fomichev/xskgen
for a more bare-bones example.
