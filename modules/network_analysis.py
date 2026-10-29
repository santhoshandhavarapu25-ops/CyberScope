
from collections import defaultdict

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


def analyze_pcap(file_path):
    """
    Analyze a PCAP file offline.

    Returns:
        packet_count: Total packets read
        protocol_summary: Counts of supported protocols
        findings: Potential security findings with recommendations
    """

    packets = rdpcap(file_path)

    findings = []
    source_ports = defaultdict(set)
    syn_counts = defaultdict(int)
    protocols = defaultdict(int)
    cleartext_indicators = set()

    # Analyze packets
    for packet in packets:
        if IP not in packet:
            continue

        src = packet[IP].src
        dst = packet[IP].dst

        protocols["IPv4"] += 1

        if TCP in packet:
            tcp = packet[TCP]
            protocols["TCP"] += 1

            # Track distinct TCP destination ports per source
            source_ports[src].add(tcp.dport)

            # Count initial SYN packets (SYN set, ACK unset)
            if tcp.flags & 0x02 and not tcp.flags & 0x10:
                syn_counts[src] += 1

            # Check for authentication-related cleartext indicators.
            # Credential values are not extracted or stored.
            if Raw in packet:
                payload = bytes(packet[Raw].load).lower()

                possible_auth = (
                    b"authorization: basic" in payload
                    or (
                        b"ftp" in payload
                        and b"pass " in payload
                    )
                    or (
                        b"login" in payload
                        and b"password" in payload
                    )
                )

                if possible_auth:
                    cleartext_indicators.add((src, dst))

        elif UDP in packet:
            protocols["UDP"] += 1

    # Detect possible port scanning
    for src, ports in source_ports.items():
        if len(ports) >= 15:
            findings.append({
                "Finding": "Possible port scan",
                "Source": src,
                "Severity": "Medium",
                "Evidence": (
                    f"Contacted {len(ports)} distinct TCP "
                    "destination ports in the capture."
                ),
                "Recommendation": (
                    "Verify whether the activity was authorized. "
                    "Review firewall logs and restrict unnecessary access."
                )
            })

    # Detect high volumes of initial SYN packets
    for src, count in syn_counts.items():
        if count >= 100:
            findings.append({
                "Finding": "High volume of TCP SYN packets",
                "Source": src,
                "Severity": "Medium",
                "Evidence": f"{count} initial TCP SYN packets observed.",
                "Recommendation": (
                    "Review connection patterns and surrounding traffic. "
                    "Confirm whether the activity is legitimate before "
                    "classifying it as malicious."
                )
            })

    # Report possible cleartext authentication indicators
    for src, dst in cleartext_indicators:
        findings.append({
            "Finding": "Possible cleartext authentication data",
            "Source": f"{src} -> {dst}",
            "Severity": "High",
            "Evidence": (
                "An authentication-related payload indicator was found. "
                "Manual verification is required."
            ),
            "Recommendation": (
                "Use encrypted protocols such as HTTPS or SSH. "
                "Disable insecure services and rotate credentials if "
                "exposure is confirmed."
            )
        })

    # Prepare protocol summary
    protocol_summary = [
        {
            "Protocol": protocol,
            "Packet Count": count
        }
        for protocol, count in sorted(protocols.items())
    ]

    return {
        "packet_count": len(packets),
        "protocol_summary": protocol_summary,
        "findings": findings
    }
