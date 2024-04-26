from scapy.layers.inet import IP, ICMP
from scapy.all import *


def icmp_scan_is(ip):
    p = IP(dst=ip) / ICMP()
    ans = sr1(p, timeout=1, verbose=0)
    if ans is None:
        return False
    elif ans.haslayer(ICMP) and ans[ICMP].type == 0 and ans[ICMP].code == 0:
        return True
    else:
        return False
