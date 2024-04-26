from tcp_syn_scan_is import tcp_syn_scan_is
from icmp_scan_is import icmp_scan_is
from threading import Thread, Lock
from printer import tcp_syn_printer

global_port_open = []
global_port_filtered = []
global_port_down = []
lock = Lock()


def tcp_syn_scan_thread(ip, p):
    try:
        rec = tcp_syn_scan_is(ip, p)
        if rec == 1:
            lock.acquire()
            global_port_filtered.append(p)
            lock.release()
        elif rec == 2:
            lock.acquire()
            global_port_down.append(p)
            lock.release()
        elif rec == 3:
            lock.acquire()
            global_port_open.append(p)
            lock.release()
        else:
            # 暂时不做处理
            pass
    except Exception:
        pass


def tcp_syn_scan_run(ip, port):
    thread_list = []
    for p in port:
        tmp = Thread(target=tcp_syn_scan_thread, args=(ip, p))
        tmp.start()
        thread_list.append(tmp)
    for t in thread_list:
        t.join()


def tcp_syn_scan(ip, port):
    print(f"Tcp syn scan is running...")
    tcp_syn_scan_run(ip, port)
    if len(global_port_down) != 0 or len(global_port_open) != 0:
        print(f"{ip} is up")
    else:
        if not icmp_scan_is(ip):
            print(
                f"{ip} can't be concluded up or down.State may be wrong.Maybe you can use other scan type to complement")
        else:
            print(f"{ip} is up")
    print("scan is over...")
    tcp_syn_printer(ip, global_port_open, global_port_filtered, global_port_down)
