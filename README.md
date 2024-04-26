# Scan
A IP/Port scanner based on Scapy in Python

-I icmp
-Ts syn
-Ta ACK
-Tf FIN
-U udp

example:
python scan.py -I 192.168.50.0/24
python scan.py -Ts 192.168.50.88 -p 80,8080,90-100
