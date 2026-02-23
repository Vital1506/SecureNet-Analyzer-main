import ipaddress
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup


def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return "Unknown"


def detect_live_hosts(local_ip):
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    target_ip = f"{network.network_address}/24"

    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_ip)
    packet = ethernet / arp

    result = srp(packet, timeout=5, verbose=False)[0]
    live_hosts = []

    for sent, received in result:
        host_info = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": get_mac_vendor(received.hwsrc)
        }
        live_hosts.append(host_info)

    if live_hosts:
        print("\nLive Hosts:")
        for host in live_hosts:
            print(f"IP: {host['ip']} | MAC: {host['mac']} | Vendor: {host['vendor']}")
    else:
        print("No live hosts found.")
