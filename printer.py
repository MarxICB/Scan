from ipaddress import IPv4Address


def tcp_fin_printer(ip, port, has_rst):
    print(f"{ip}:")
    port.sort(key=lambda x: int(x))
    if has_rst == 1:
        if len(port) == 0:
            print("None is open|filtered")
            return
        print("PORT\tSTATE")
        for p in port:
            print(f"{p}\topen|filtered")
    else:
        if len(port) == 0:
            print("None is open|filtered")
            return
        print("PORT\tSTATE")
        for p in port:
            print(f"{p}\topen|filtered")


def tcp_syn_printer(ip, port_open, port_filtered, port_down):
    print(f"{ip}:")
    port_open.sort(key=lambda x: int(x))
    port_filtered.sort(key=lambda x: int(x))
    port_down.sort(key=lambda x: int(x))
    if len(port_open) == 0 and len(port_filtered) == 0:
        print("None is filtered")
        return
    print("PORT\tSTATE")
    for p in port_open:
        print(f"{p}\topen")
    for p in port_filtered:
        print(f"{p}\tfiltered")


def tcp_ack_printer(ip, port_filtered):
    print(f"{ip}:")
    port_filtered.sort(key=lambda x: int(x))
    if len(port_filtered) == 0:
        print("None is filtered")
        return
    print("PORT\tSTATE")
    for p in port_filtered:
        print(f"{p}\tfiltered")


def udp_printer(ip, port_open, port_filtered):
    print(f"{ip}:")
    port_open.sort(key=lambda x: int(x))
    port_filtered.sort(key=lambda x: int(x))
    if len(port_open) == 0 and len(port_filtered) == 0:
        print("None is open")
        return
    print("PORT\tSTATE")
    for p in port_open:
        print(f"{p}\topen")
    for p in port_filtered:
        print(f"{p}\tfiltered|datagram need specified content")


def ip_printer(ip):
    ip.sort(key=lambda x: IPv4Address(x))
    length = len(ip)
    if length >= 2:
        print(f"{length} IPs are detected up:")
        for i in ip:
            print(i)
    elif length == 1:
        print(f"{ip[0]} is up")
    else:
        print("None ip is up")
