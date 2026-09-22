import ipaddress
import re

from scapy.all import IP, IPv6, TCP, UDP, ICMP


IPV4_CONDITION_RE = re.compile(
    r"(?P<direction>src|dst)\s+host\s+(?P<ip>\S+)", re.IGNORECASE
)
PORT_CONDITION_RE = re.compile(
    r"(?P<direction>src|dst)\s+port\s+(?P<port>\d+)", re.IGNORECASE
)
PROTOCOL_CONDITION_RE = re.compile(
    r"(?P<protocol>tcp|udp|icmp|icmp6|ip|ipv6)\b", re.IGNORECASE
)


def _validate_ipv4(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def _validate_ipv6(address):
    try:
        ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def packet_filter(packet, filter_criteria):
    if not filter_criteria:
        return True

    has_ip = packet.haslayer(IP)
    has_ipv6 = packet.haslayer(IPv6)

    if 'src_ip' in filter_criteria:
        candidate = None
        if has_ip:
            candidate = packet[IP].src
        elif has_ipv6:
            candidate = packet[IPv6].src
        if candidate != filter_criteria['src_ip']:
            return False

    if 'dst_ip' in filter_criteria:
        candidate = None
        if has_ip:
            candidate = packet[IP].dst
        elif has_ipv6:
            candidate = packet[IPv6].dst
        if candidate != filter_criteria['dst_ip']:
            return False

    if 'src_port' in filter_criteria:
        if not packet.haslayer(TCP) and not packet.haslayer(UDP):
            return False
        sport = None
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
        if sport != filter_criteria['src_port']:
            return False

    if 'dst_port' in filter_criteria:
        if not packet.haslayer(TCP) and not packet.haslayer(UDP):
            return False
        dport = None
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport
        if dport != filter_criteria['dst_port']:
            return False

    if 'protocol' in filter_criteria:
        expected = filter_criteria['protocol'].lower()
        protocol_name = _protocol_name(packet)
        if protocol_name != expected:
            return False

    return True


def _protocol_name(packet):
    if packet.haslayer(TCP):
        return 'tcp'
    if packet.haslayer(UDP):
        return 'udp'
    if packet.haslayer(IPv6) and packet[IPv6].nh == 58:
        return 'icmp6'
    if packet.haslayer(ICMP):
        return 'icmp'
    if packet.haslayer(IPv6):
        return 'ipv6'
    if packet.haslayer(IP):
        return 'ip'
    return 'unknown'


def parse_filter_string(filter_str):
    """Parse the explicit filter language and reject unsupported input."""
    if filter_str is None or filter_str.strip().lower() == "all":
        return None

    filter_dict = {}
    conditions = re.split(r"\s+and\s+", filter_str.strip(), flags=re.IGNORECASE)

    for condition in conditions:
        condition = condition.strip()
        if not condition:
            raise ValueError("Empty filter condition is not allowed.")

        ip_match = IPV4_CONDITION_RE.fullmatch(condition)
        if ip_match:
            ip = ip_match.group("ip")
            if not (_validate_ipv4(ip) or _validate_ipv6(ip)):
                raise ValueError(f"Invalid IP address in filter: {ip}")
            filter_dict[f"{ip_match.group('direction')}_ip"] = ip
            continue

        port_match = PORT_CONDITION_RE.fullmatch(condition)
        if port_match:
            port = int(port_match.group("port"))
            if not 1 <= port <= 65535:
                raise ValueError(f"Port must be between 1 and 65535: {port}")
            filter_dict[f"{port_match.group('direction')}_port"] = port
            continue

        protocol_match = PROTOCOL_CONDITION_RE.fullmatch(condition)
        if protocol_match:
            filter_dict["protocol"] = protocol_match.group("protocol").lower()
            continue

        raise ValueError(f"Unsupported filter condition: {condition}")

    return filter_dict
