__author__ = 'Yuxibro'
import logging
import socket
logging.getLogger("scapy").setLevel(1)
from scapy.all import conf,sendp,srp1,ICMP,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random,send,RandMAC


packetCount = 0 # count the packet...
def replyRandomTTL(packet):
    global packetCount
    packetCount += 1
    packet.show()

    if packet[IP].ttl <=1 :
        print("sup dude!!!")
    else:
        newTTL = packet[IP].ttl - 1     # Decrement TTL
        packet[IP].ttl = newTTL
        del packet[IP].chksum           # Delete Checksum for recalculation
        packet.show2()                  # Show2() allow recalculate checksum
        send(packet)                    # Send out the packet
    return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)
## Setup sniff, filtering for IP traffic filter="icmp and host 66.35.250.151"
print("Sniffing...")
sniff(iface="en0",filter="ip",prn=replyRandomTTL)

