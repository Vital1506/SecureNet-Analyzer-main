import os

BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'blocked_ips.txt')


def load_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        return []

    with open(BLOCKLIST_FILE, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file if line.strip()]


def save_blocklist(blocked_ips):
    with open(BLOCKLIST_FILE, 'w', encoding='utf-8') as file:
        for ip in blocked_ips:
            file.write(f"{ip}\n")


def add_ip_to_blocklist(ip):
    blocked = load_blocklist()
    clean_ip = ip.strip()
    if not clean_ip:
        return False
    if clean_ip not in blocked:
        blocked.append(clean_ip)
        save_blocklist(blocked)
        return True
    return False


def remove_ip_from_blocklist(ip):
    blocked = load_blocklist()
    clean_ip = ip.strip()
    if clean_ip in blocked:
        blocked.remove(clean_ip)
        save_blocklist(blocked)
        return True
    return False


def clear_blocklist():
    save_blocklist([])


def is_blocked_ip(ip):
    return ip in load_blocklist()
