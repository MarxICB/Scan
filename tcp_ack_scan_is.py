from scapy.layers.inet import IP, TCP, sr1


# False 没被过滤 True 被过滤
def tcp_ack_scan_is(ip: str, port: str) -> bool:
    p = IP(dst=ip) / TCP(dport=int(port), flags="A")
    ans = sr1(p, timeout=1, verbose=0)
    # ans.display()
    if ans is None:
        return True
    if 'R' in ans[TCP].flags:
        return False


if __name__ == "__main__":
    ip1 = '192.168.50.88'
    port1 = "135"
    tcp_ack_scan_is(ip1, port1)
