from scapy.all import *

import tls
import client


# for offline testing
def main():
    pkts = rdpcap("test1.3.pcapng")
    pkt_list = PacketList([p for p in pkts])
    cap = Captured(pkt_list)
    clienthello = cap.next_packet()
    serverhello = cap.next_packet()
    ch_bytes = bytes(clienthello[TCP].payload)
    sh_bytes = bytes(serverhello[TCP].payload)
    cho = tls.ClientHello.from_bytes(ch_bytes)
    cho, sho = client.verify_response(cho, sh_bytes)
    return


class Captured:
    plist: PacketList
    counter: int
    
    def __init__(self, plist):
        self.plist = plist
        self.counter = 0
        
        
    def next_packet(self) -> Packet:
        self.counter += 1
        if self.counter >= len(self.plist):
            return None
        return self.plist[self.counter]


if __name__ == "__main__":
    main()