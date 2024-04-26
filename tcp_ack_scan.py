from tcp_ack_scan_is import tcp_ack_scan_is
from icmp_scan_is import icmp_scan_is
from threading import Thread, Lock
from printer import tcp_ack_printer

global_port_filtered = []
lock = Lock()
has_rst = 0


def tcp_ack_scan_thread(ip, p):
    global global_port_filtered, has_rst
    try:
        if tcp_ack_scan_is(ip, p):
            lock.acquire()
            global_port_filtered.append(p)
            lock.release()
        else:
            if has_rst == 0:
                has_rst = 1
    except Exception:
        pass


def tcp_ack_scan_run(ip, port):
    thread_list = []
    for p in port:
        tmp = Thread(target=tcp_ack_scan_thread, args=(ip, p))
        tmp.start()
        thread_list.append(tmp)
    for t in thread_list:
        t.join()


def tcp_ack_scan(ip, port):
    print(f"Tcp ack scan is running...")
    tcp_ack_scan_run(ip, port)
    if has_rst == 1:
        print(f"{ip} is up")
    else:
        if not icmp_scan_is(ip):
            print(
                f"{ip} can't be concluded up or down.State may be wrong.Maybe you can use other scan type to complement")
        else:
            print(f"{ip} is up")
    print("scan is over...")
    tcp_ack_printer(ip, global_port_filtered)
