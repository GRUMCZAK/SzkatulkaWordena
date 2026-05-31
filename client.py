from scapy.all import *


DST_IP = "192.168.0.62"
DST_PORT = 1920
SRC_PORT = 1918
client_seq = 1000
ack = -1


response = None

def insert_pkt(pkt):
    global response 
    response = pkt


# we send an SYN and expect to receive a SYN-ACK back
send( 
    IP(dst=DST_IP) /
    TCP(
        sport = SRC_PORT,
        dport = DST_PORT,
        flags = "S",
        seq = client_seq
    ), 
    verbose=0
)
client_seq += 1 # we've sent SYN, so we have to increment our seq
print("[+] SYN sent")

# take the first packet that came to port number 1918
sniff(filter = f"tcp and dst port {SRC_PORT}", prn=insert_pkt, count = 1, store=0)

if response is None:
    print("No answer from server")
    exit()

if "S" in response[TCP].flags and "A" in response[TCP].flags:
    print("[+] SYN + ACK received")

#print(f"Flags in response are: {response[TCP].flags}")
server_seq = response[TCP].seq
ack = response[TCP].ack

send( 
    IP(dst=DST_IP) /
    TCP(
        sport = SRC_PORT,
        dport = DST_PORT,
        flags = "A",
        seq = client_seq,
        ack = ack
    ), 
    verbose=0
)
client_seq += 1 
print("[+] ACK sent")
print("[+] Connection established")

while True:
    data = input("> ") # proper formatting required to put data variable as the data in TCP segment
    send( 
        IP(dst=DST_IP) /
        TCP(
            sport = SRC_PORT,
            dport = DST_PORT,
            seq = client_seq,
            flags = "PA",
            ack = ack
        ) /
        data.encode(),
        verbose=0
    )
    client_seq += len(data)
    sniff(filter = f"tcp and dst port {SRC_PORT}", prn=insert_pkt, count = 1, store = 0 )
    ack = response[TCP].ack
    print(response.show())
