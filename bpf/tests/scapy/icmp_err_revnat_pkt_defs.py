# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

icmp4_err_frag_needed_for_revnat = (
    Ether(
        src=mac_one,
        dst=mac_two,
    )
    /
    # outer IPv4 (router -> host)
    IP(
        src=v4_node_two,
        dst=v4_node_one,
    )
    /
    # ICMP Destination Unreachable / Fragmentation Needed
    ICMP(
        type=3,
        code=4,
        nexthopmtu=1500,
    )
    /
    # embedded original IPv4 + TCP
    IP(
        src=v4_node_one,
        dst=v4_node_two,
        flags="DF",
    )
    /
    TCP(
        sport=32768,  # NODEPORT_PORT_MIN_NAT (SNAT'd port)
        dport=80,
    )
)


icmp4_err_frag_needed_after_revnat = (
    Ether(src=mac_one, dst=mac_two) /
    IP(
        src=v4_node_two,      # router
        dst=v4_ext_one,       # endpoint (rev-NAT)
    ) /
    ICMP(
        type=3,
        code=4,
        nexthopmtu=1500,
    ) /
    IP(
        src=v4_ext_one,       # rev-NAT
        dst=v4_node_two,
        flags="DF",
    ) /
    TCP(
        sport=3030,           # original port restored
        dport=80,
    )
)