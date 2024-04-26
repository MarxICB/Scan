import argparse
import ipaddress
import sys
from icmp_scan import icmp_scan
from intranet import intranet
from tcp_syn_scan import tcp_syn_scan
from tcp_fin_scan import tcp_fin_scan
from tcp_ack_scan import tcp_ack_scan
from udp_scan import udp_scan


def port_list(ports):
    new_port_list = []
    if "," in ports:
        temp_list = ports.split(",")
        for port in temp_list:
            if "-" in port:
                for p in range(int(port.split("-")[0]), int(port.split("-")[1]) + 1):
                    new_port_list.append(p)
            else:
                new_port_list.append(port)

    elif "-" in ports:
        for p in range(int(ports.split("-")[0]), int(ports.split("-")[1]) + 1):
            new_port_list.append(p)

    else:
        new_port_list.append(ports)
    if len(new_port_list) > 512:
        print("It's too more")
        sys.exit()
    return new_port_list


def ip_list(ip):
    new_ip_list = []
    if "," in ip:
        temp_ip = ip.split(",")
    else:
        temp_ip = [ip]
    for ip_string in temp_ip:
        if '/' in ip_string:  # CIDR notation
            network = ipaddress.ip_network(ip_string, strict=False)
            for ip in network.hosts():
                new_ip_list.append(str(ip))
        else:  # Single IP address
            new_ip_list.append(ip_string)
    if len(new_ip_list) > 512:
        print("It's too more")
        sys.exit()
    return new_ip_list


"""
-I icmp
-Ts syn
-Ta ACK
-Tf FIN
-U udp
"""


def main():
    parser = argparse.ArgumentParser(description='A network scanning gadget.')

    # 互斥组：扫描类型
    scan_type_group = parser.add_mutually_exclusive_group()
    scan_type_group.add_argument('-I', '--icmp', action='store_true', help='ICMP SCAN')
    scan_type_group.add_argument('-Ts', '--syn', action='store_true', help='TCP SYN SCAN')
    scan_type_group.add_argument('-Ta', '--ack', action='store_true', help='TCP ACK SCAN')
    scan_type_group.add_argument('-Tf', '--fin', action='store_true', help='TCP FIN SCAN')
    scan_type_group.add_argument('-U', '--udp', action='store_true', help='UDP SCAN')

    default_ports = '21,22,23,25,53,69,80,109,110,135,139,161,179,213,443,445,1521,3306,5000,6379,8000,8080,8848,9000'
    parser.add_argument('ip', type=str, help='IP to scan')
    parser.add_argument('-p', '--port', type=str, default=default_ports, help='Port to scan')

    args = parser.parse_args()
    ip = ip_list(args.ip)
    port = port_list(args.port)
    if args.icmp:
        icmp_scan(ip)
        return
    elif args.udp:
        if args.port == default_ports:
            print("need port! -p PORT[,PORT]|PORT-PROT")
            exit(0)
        udp_scan(ip[0], port)
        return
    if args.port == default_ports:
        print("The port parameter is not specified, scanning the default ports:")
        print(default_ports)
    ip = ip[0]
    intranet(ip)
    if args.syn:
        tcp_syn_scan(ip, port)
    elif args.ack:
        tcp_ack_scan(ip, port)
    elif args.fin:
        tcp_fin_scan(ip, port)
    else:
        tcp_syn_scan(ip, port)


if __name__ == '__main__':
    main()
