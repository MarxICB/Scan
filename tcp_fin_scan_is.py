from scapy.layers.inet import IP, TCP, sr1
from ipaddress import ip_address


# True 开启或者过滤 False 未开启
def tcp_fin_scan_is(ip, port):
    # 创建 TCP FIN 包
    p = IP(dst=str(ip_address(ip))) / TCP(dport=int(port), flags="F")
    # 发送包并等待响应
    ans = sr1(p, timeout=2, verbose=0)
    # 根据响应判断端口状态
    if ans is None:
        # 没有响应通常表示端口是开放的或者过滤的
        return True
    else:
        # 有回复算作关了
        return False


if __name__ == '__main__':
    ip = '192.168.50.88'
    #   ip='127.0.0.1'
    port = '80'
    result = tcp_fin_scan_is(ip, port)

    if result is True:
        print(ip, "port", port, "is open.")
    elif result is False:
        print(ip, "port", port, "is closed.")
    else:
        print("Unable to determine the status of the port.")
