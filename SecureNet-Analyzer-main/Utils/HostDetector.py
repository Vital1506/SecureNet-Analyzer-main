import ipaddress
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup


_MAX_SCAN_HOSTS = 254


def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except Exception:  # third-party MAC lookup can raise library-specific errors
        return "Unknown"


def detect_live_hosts(local_ip, timeout=5, max_hosts=_MAX_SCAN_HOSTS):
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not 1 <= max_hosts <= _MAX_SCAN_HOSTS:
        raise ValueError(f"max_hosts must be between 1 and {_MAX_SCAN_HOSTS}")
    try:
        address = ipaddress.IPv4Address(local_ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError("local_ip must be a valid IPv4 address") from exc

    network = ipaddress.IPv4Network(f"{address}/24", strict=False)
    target_ip = f"{network.network_address}/24"

    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_ip)
    packet = ethernet / arp

    result = srp(packet, timeout=timeout, verbose=False)[0]
    live_hosts = []

    for sent, received in result:
        if len(live_hosts) >= max_hosts:
            break
        host_info = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": get_mac_vendor(received.hwsrc)
        }
        live_hosts.append(host_info)

    print(f"\nLive Host Scan — target: {target_ip} | timeout: {timeout}s | max hosts: {max_hosts}")
    if live_hosts:
        print(f"Live hosts found: {len(live_hosts)}")
        for host in live_hosts:
            print(f"  IP: {host['ip']} | MAC: {host['mac']} | Vendor: {host['vendor']}")
    else:
        print("No live hosts found.")
