# Scan
A IP/Port scanner based on Scapy in Python
 <br />
-I Icmp <br />
-Ts SYN <br />
-Ta ACK <br />
-Tf FIN <br />
-U Udp

example: <br />
python scan.py -I 192.168.50.0/24 <br />
python scan.py -Ts 192.168.50.88 -p 80,8080,90-100
