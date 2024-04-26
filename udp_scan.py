from threading import Thread, Lock
from icmp_scan_is import icmp_scan_is
from printer import udp_printer
from udp_scan_is import udp_scan_is

global_port_open = []
global_port_open_filtered = []
lock = Lock()

has_not_none = 0


def udp_scan_thread(ip, p):
    global has_not_none
    try:
        rec = udp_scan_is(ip, p)
        lock.acquire()
        if rec == 1:
            global_port_open.append(p)
            if has_not_none == 0:
                has_not_none = 1
        elif rec == 2:
            global_port_open_filtered.append(p)
        else:
            if has_not_none == 0:
                has_not_none = 1
        lock.release()
    except Exception:
        pass


def udp_scan_run(ip, port):
    thread_list = []
    for p in port:
        tmp = Thread(target=udp_scan_thread, args=(ip, p))
        tmp.start()
        thread_list.append(tmp)
    for t in thread_list:
        t.join()


def udp_scan(ip, port):
    print(f"udp scan is running...")
    udp_scan_run(ip, port)
    if has_not_none == 1:
        print(f"{ip} is up")
    else:
        if not icmp_scan_is(ip):
            print(
                f"{ip} can't be concluded up or down.State may be wrong.Maybe you can use other scan type to complement")
        else:
            print(f"{ip} is up")
    print("scan is over...")
    udp_printer(ip, global_port_open, global_port_open_filtered)
