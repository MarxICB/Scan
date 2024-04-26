from scapy.layers.inet import IP, TCP, sr1


def tcp_syn_scan_is(ip, port):
    # 构建 SYN 数据包
    ip_layer = IP(dst=ip)
    tcp_layer = TCP(dport=int(port), flags='S')
    packet = ip_layer / tcp_layer

    # 发送 SYN 数据包并等待响应
    ans = sr1(packet, timeout=2, verbose=0)
    # 检查响应
    if ans is None:
        # 没有收到响应或超时 判定过滤
        return 1
    elif ans.haslayer(TCP) and 'R' in ans.getlayer(TCP).flags:
        # 收到R 则为关闭
        return 2
    elif ans.haslayer(TCP) and 'S' in ans.getlayer(TCP).flags:
        # 收到S 则为开启
        return 3
    else:
        # 其他情况暂没遇到，不处理了
        return 0


if __name__ == '__main__':
    ip = "192.168.50.87"  # IP 地址已经是字符串格式
    port = "135"  # 假设我们要扫描的端口是 22，这是整数
    is_open = tcp_syn_scan_is(ip, port)
