from scapy.all import *

DST_IP = "192.168.0.62"
DST_PORT = 1918
SRC_PORT = 1920
server_seq = 2000
ack = -1

response = None

def insert_pkt(pkt):
    global response 
    response = pkt


print("Listening for connection attempts...")

sniff(filter = f"tcp and dst port {SRC_PORT}", prn=insert_pkt, count = 1, store=0)
print("Listening for connection attempts...2")


print(response[TCP].flags)
if "S" not in response[TCP].flags:
    print("Attempt to connect without a SYN flag. Exiting...")
    exit()
print("[+] SYN received")
ack = response[TCP].ack

send(
    IP(dst=DST_IP) /
    TCP(
        sport = SRC_PORT,
        dport = DST_PORT,
        flags = "SA",
        seq = server_seq,
        ack = ack
    ), 
    verbose=0
)
server_seq += 1
print("[+] SYN+ACK sent")

sniff(filter = f"tcp and dst port {SRC_PORT}", prn=insert_pkt, count = 1, store=0)

if "A" not in response[TCP].flags:
    print("Attempt to connect without an ACK flag. Exiting...")
    exit()
#print(response.show())
print("[+] ACK received")
print("[+] Connection established")
ack = response[TCP].ack

while True:
    sniff(filter = f"tcp and dst port {SRC_PORT}", count = 1, store = 0)
    print("odebrano")
    print(response.show())
    data = input()
    send(
        IP(dst=DST_IP) /
        TCP(
            sport = SRC_PORT,
            dport = DST_PORT,
            seq = server_seq,
            ack = ack
        ), 
        data.encode(),
        verbose=0
    )
    server_seq += len(data)
    print(response)

