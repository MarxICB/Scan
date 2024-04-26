from scapy.all import *
from scapy.layers.inet import IP, UDP


def udp_scan_is(ip, port):
    sport = random.randint(6000, 65535)
    udp_scan_resp = sr1(IP(dst=ip) / UDP(dport=int(port), sport=sport), timeout=1, verbose=0)
    if udp_scan_resp is None:
        # 没返回就是过滤
        return 2
    elif udp_scan_resp.haslayer(UDP):
        # udp返回UDP包则说明开
        return 1
    else:
        # 这里不出意外是返回icmp，说明没开
        return 3


if __name__ == "__main__":
    target = "192.168.50.225"
    port = 66
    udp_scan_is(target, port)
