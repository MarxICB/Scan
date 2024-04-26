from threading import Thread, Lock
from icmp_scan_is import icmp_scan_is
from printer import tcp_fin_printer
from tcp_fin_scan_is import tcp_fin_scan_is

global_port_filtered_or_open = []
lock = Lock()

global_has_rst = 0


def tcp_fin_scan_thread(ip, p):
    global global_port_filtered_or_open, global_has_rst
    try:
        if tcp_fin_scan_is(ip, p):
            lock.acquire()
            global_port_filtered_or_open.append(p)
            lock.release()
        else:
            lock.acquire()
            global_has_rst = 1
            lock.release()
    except Exception:
        pass


def tcp_fin_scan_run(ip, port):
    global global_port_filtered_or_open
    thread_list = []
    for p in port:
        tmp = Thread(target=tcp_fin_scan_thread, args=(ip, p))
        tmp.start()
        thread_list.append(tmp)
    for t in thread_list:
        t.join()


def tcp_fin_scan(ip, port):
    global global_port_filtered_or_open, global_has_rst
    print(f"Tcp fin scan is running...")
    print("Note:it is based on Linux.Win may be wrong.")

    tcp_fin_scan_run(ip, port)

    if global_has_rst == 1:
        print(f"{ip} is up")
    else:
        if not icmp_scan_is(ip):
            print(
                f"{ip} can't be concluded up or down.State may be wrong.Maybe you can use other scan type to complement")
        else:
            print(f"{ip} is up")
    print("scan is over...")
    tcp_fin_printer(ip, global_port_filtered_or_open, global_has_rst)
