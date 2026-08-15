"""
Real network traffic collector (Feature 1).

Captures live packets with Scapy over a fixed time window, aggregates them
per source IP, and emits dicts shaped exactly like backend.app.schemas.flow.TrafficFlow
so they can be fed straight into analyze_flow().

Only features that can genuinely be derived from packet headers are computed.
See FAILED_LOGINS_NOT_COLLECTED and LABEL_PLACEHOLDER_FOR_SCHEMA below for the
two schema fields that are NOT network-observable.

Windows: requires Npcap (see project README) and an elevated process.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from scapy.all import IP, IPv6, TCP, UDP, sniff

DEFAULT_WINDOW_SECONDS = 10
# Capture IPv4 + IPv6 only; ARP/other L2 noise is not part of the feature set.
DEFAULT_BPF_FILTER = "ip or ip6"

# --- Fields NOT derivable from network packets -------------------------------
# failed_logins comes from authentication logs (Windows Security Event ID 4625),
# not from the wire. Reported as 0 = "not measured by this collector", to be
# populated by the auth-log feature later. This is not an estimate.
FAILED_LOGINS_NOT_COLLECTED = 0

# label is ground-truth annotation used for training/evaluation. A live sensor
# cannot know it - inferring it is the detector's job. The TrafficFlow schema
# requires ^(normal|attack)$, so we emit the schema-valid placeholder.
# If detector.score_one() consumes 'label' as a feature, exclude it there.
LABEL_PLACEHOLDER_FOR_SCHEMA = "normal"
# -----------------------------------------------------------------------------

MAX_DST_PORTS = 65535  # schema upper bound on unique_dst_ports


class _HostStats:
    """Per-source-IP accumulator for one capture window."""

    __slots__ = (
        "bytes_sent",
        "bytes_recv",
        "tcp_packets_sent",
        "syn_packets_sent",
        "dst_ports",
        "connections",
    )

    def __init__(self) -> None:
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.tcp_packets_sent = 0
        self.syn_packets_sent = 0
        self.dst_ports = set()
        # connection key -> [first_seen_epoch, last_seen_epoch]
        self.connections: Dict[tuple, List[float]] = {}

    def touch_connection(self, key: tuple, ts: float) -> None:
        window = self.connections.get(key)
        if window is None:
            self.connections[key] = [ts, ts]
        else:
            window[1] = ts

    @property
    def syn_ratio(self) -> float:
        """SYN packets sent / TCP packets sent. High values indicate scanning
        or SYN flooding (many half-open handshakes, few completed)."""
        if self.tcp_packets_sent == 0:
            return 0.0
        return min(self.syn_packets_sent / self.tcp_packets_sent, 1.0)

    @property
    def avg_conn_duration(self) -> float:
        """Mean last-packet-minus-first-packet across observed connections.
        Connections still open at window close are truncated; single-packet
        connections are 0.0. Both are measurement limits, not estimates."""
        if not self.connections:
            return 0.0
        total = sum(last - first for first, last in self.connections.values())
        return max(total / len(self.connections), 0.0)


class FlowCollector:
    """Sniffs one time window and returns TrafficFlow-compatible dicts."""

    def __init__(
        self,
        iface: Optional[str] = None,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        bpf_filter: str = DEFAULT_BPF_FILTER,
    ) -> None:
        self.iface = iface
        self.window_seconds = window_seconds
        self.bpf_filter = bpf_filter
        self._hosts: Dict[str, _HostStats] = defaultdict(_HostStats)

    # -- packet handling ------------------------------------------------------

    def _handle_packet(self, pkt) -> None:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            proto = int(pkt[IP].proto)
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
            proto = int(pkt[IPv6].nh)
        else:
            return

        size = len(pkt)
        ts = float(pkt.time)

        sender = self._hosts[src]
        sender.bytes_sent += size
        # Every host is also credited for what it receives, so a host that both
        # sends and receives gets accurate bytes_sent AND bytes_recv.
        self._hosts[dst].bytes_recv += size

        if TCP in pkt:
            tcp = pkt[TCP]
            sender.tcp_packets_sent += 1
            flags = int(tcp.flags)
            # SYN set, ACK clear => connection initiation attempt
            if (flags & 0x02) and not (flags & 0x10):
                sender.syn_packets_sent += 1
            sender.dst_ports.add(int(tcp.dport))
            key = ("tcp", dst, int(tcp.dport), int(tcp.sport))
        elif UDP in pkt:
            udp = pkt[UDP]
            sender.dst_ports.add(int(udp.dport))
            key = ("udp", dst, int(udp.dport), int(udp.sport))
        else:
            # ICMP and friends: no ports, treat the host pair as one "connection"
            key = ("ip", dst, proto)

        sender.touch_connection(key, ts)

    # -- collection -----------------------------------------------------------

    def collect(self) -> List[Dict[str, Any]]:
        """Blocks for window_seconds, then returns one flow dict per source IP,
        busiest first. Returns [] if no traffic was observed."""
        self._hosts.clear()

        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._handle_packet,
            timeout=self.window_seconds,
            store=False,
        )

        window_end = datetime.now()
        flows = [
            self._build_flow(ip, stats, window_end)
            for ip, stats in self._hosts.items()
            if stats.bytes_sent > 0  # only hosts actually seen as a source
        ]
        flows.sort(key=lambda f: f["bytes_sent"], reverse=True)
        return flows

    @staticmethod
    def _build_flow(ip: str, stats: _HostStats, window_end: datetime) -> Dict[str, Any]:
        return {
            "timestamp": window_end,
            "src_ip": ip,
            "num_connections": len(stats.connections),
            "unique_dst_ports": min(len(stats.dst_ports), MAX_DST_PORTS),
            "bytes_sent": float(stats.bytes_sent),
            "bytes_recv": float(stats.bytes_recv),
            "failed_logins": FAILED_LOGINS_NOT_COLLECTED,
            "syn_ratio": round(stats.syn_ratio, 4),
            "avg_conn_duration": round(stats.avg_conn_duration, 3),
            "label": LABEL_PLACEHOLDER_FOR_SCHEMA,
        }


# -- module-level convenience API ---------------------------------------------


def collect_flows(
    iface: Optional[str] = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """All source IPs observed in one window, busiest first."""
    return FlowCollector(iface=iface, window_seconds=window_seconds).collect()


def collect_primary_flow(
    iface: Optional[str] = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> Optional[Dict[str, Any]]:
    """The single busiest flow, or None if nothing was captured. This is what
    the single-flow React readout will consume."""
    flows = collect_flows(iface=iface, window_seconds=window_seconds)
    return flows[0] if flows else None


def list_interfaces() -> List[Dict[str, Any]]:
    """Capture-capable interfaces. On Windows the 'name' field is what you pass
    as iface=."""
    try:
        from scapy.arch.windows import get_windows_if_list

        return [
            {"name": i.get("name"), "description": i.get("description"), "ips": i.get("ips")}
            for i in get_windows_if_list()
        ]
    except ImportError:
        from scapy.all import get_if_list

        return [{"name": n} for n in get_if_list()]


if __name__ == "__main__":
    # Smoke test:  python -m backend.app.services.traffic_collector
    import json

    print("Interfaces:")
    for entry in list_interfaces():
        print("  ", entry)

    print(f"\nCapturing for {DEFAULT_WINDOW_SECONDS}s ...")
    captured = collect_flows()
    print(f"{len(captured)} flow(s) observed\n")
    for f in captured[:5]:
        print(json.dumps(f, indent=2, default=str))