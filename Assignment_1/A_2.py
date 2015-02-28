#!/usr/bin/python
import logging

logging.getLogger("scapy").setLevel(1)
from scapy.all import conf,sendp,srp1,ICMP,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random,send,RandMAC


packetCount = 0 # count the packet...
def replyRandomTTL(packet):
    global packetCount
    packetCount += 1
    packet.show()
    originalIPSrc = packet[IP].src
    originalIPDst = packet[IP].dst
    originalMACSrc = packet[Ether].src
    originalMACDst = packet[Ether].dst
    #newPacket = IP(src=originalSrc,dst=originalDst,ttl=random.randint(1,100))/ICMP(type="echo-reply")
    #newPacket.show()
    #send()
    #replyPacket = eval(packet[1].command())
    if packet[ICMP].type == 8:

        replyPacket = eval(packet[1].command())
        #replyPacket = packet
        replyPacket[IP].src = originalIPDst
        replyPacket[IP].dst = originalIPSrc
        #replyPacket[Ether].dst = originalMACSrc
        #replyPacket[Ether].src = originalMACDst
        del replyPacket[IP].ttl
        replyPacket[IP].ttl = random.randint(1,100)
        del replyPacket[ICMP].chksum
        replyPacket[ICMP].type = 0          # 0 As echo-reply
        print("Sending back:")
        replyPacket.show2()
        del packet
        send(replyPacket)
    return #"Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)
## Setup sniff, filtering for IP traffic filter="icmp and host 66.35.250.151"
print("Sniffing...")
sniff(iface="en0",filter="icmp",prn=replyRandomTTL)