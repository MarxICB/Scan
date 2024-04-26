import ipaddress
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp1


# addresses = [
#     '192.168.50.1',
# ]
#
# for ip in addresses:
#     address = ipaddress.ip_address(ip)
#     print("IP地址：", address)
#     print("IP Version:", address.version)
#     print("是否是专用地址:", address.is_private)
#     print("是否是公网地址:", address.is_global)
#     print("是否是多播地址:", address.is_multicast)
#     print("是否是环回地址:", address.is_loopback)
#     print("是否是link-local保留:", address.is_link_local)
#     print("判断地址是否未指定:", address.is_unspecified)
#     print("IP地址16进制:", binascii.hexlify(address.packed))
def intranet(ip):
    address = ipaddress.ip_address(ip)
    if address.is_global:
        pass
    elif address.is_private:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        # 发送ARP请求并接收响应
        answered = srp1(packet, timeout=1, retry=3, verbose=0)
        if answered is None:
            print("ARP query for the internal network address failed")
            exit(0)
    else:
        print("IP need global or private address")
        exit(0)

# intranet('192.168.50.88')
