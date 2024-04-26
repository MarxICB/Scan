from icmp_scan_is import icmp_scan_is
from threading import Thread, Lock
from printer import ip_printer
import time

global_icmp_ip_on = []
lock_icmp = Lock()


def icmp_scan_thread(ip):
    global global_icmp_ip_on
    try:
        if icmp_scan_is(ip):
            lock_icmp.acquire()
            global_icmp_ip_on.append(ip)
            lock_icmp.release()
    except Exception:
        pass


def icmp_scan(ip):
    global global_icmp_ip_on
    print(f"Icmp scan is running...")
    thread_list = []
    timestamp = 0
    for i in ip:
        tmp = Thread(target=icmp_scan_thread, args=(i,))
        tmp.start()
        thread_list.append(tmp)
        timestamp += 1
        if timestamp == 50:
            time.sleep(2)
            timestamp = 0
    for t in thread_list:
        t.join()
    print("Scan is over...")
    ip_printer(global_icmp_ip_on)
