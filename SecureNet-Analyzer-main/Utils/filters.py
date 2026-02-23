from scapy.all import IP, ICMP, TCP, UDP


def packet_filter(packet, filter_criteria):
    if not filter_criteria:
        return True

    if 'src_ip' in filter_criteria:
        if packet.haslayer(IP) and packet[IP].src != filter_criteria['src_ip']:
            return False

    if 'dst_ip' in filter_criteria:
        if packet.haslayer(IP) and packet[IP].dst != filter_criteria['dst_ip']:
            return False

    return True


def parse_filter_string(filter_str):
    if filter_str == "all":
        return None

    filter_dict = {}
    conditions = filter_str.split(' and ')

    for condition in conditions:
        condition = condition.strip().lower()

        if condition.startswith('src host'):
            ip = condition.split(' ')[2]
            filter_dict['src_ip'] = ip

        elif condition.startswith('dst host'):
            ip = condition.split(' ')[2]
            filter_dict['dst_ip'] = ip

    return filter_dict
