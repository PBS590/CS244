from scapy.all import *

sport = 35555
dport = 80
init_seq = 1000
dst = "171.67.215.200"

ip = IP(dst=dst)
SYN=TCP(sport=sport, dport=dport, flags="S", seq=init_seq)
SYNACK=sr1(ip/SYN)

ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack + 1, ack=SYNACK.seq + 1)
send_res = sr1(ip/ACK)

def print_packet(packet):
    sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.seq% %TCP.ack%")

SYNACK.show()
send_res.show()

# a=sniff(filter="src " + dst, prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.seq% %TCP.ack%"))







