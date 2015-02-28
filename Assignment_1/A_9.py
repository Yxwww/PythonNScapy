__author__ = 'Yuxibro'
from scapy.all import conf,sendp,srp1,ICMP,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random,send,RandMAC,TCP,sr,sr1
import logging
import socket
import time

ReplyPacketInfo = {'src':"",'dst':"",'type':3,"ttl":0,"code":10}

#TODO: TEST!!!
def random_reject(pkt):
    print "in the reject"
    if pkt[ICMP].type == 8:
        #pkt.show()
        ReplyPacketInfo['dst'] = pkt[IP].src
        ReplyPacketInfo['src'] = pkt[IP].dst
        ReplyPacketInfo['ttl'] = pkt[IP].ttl
        replyPacket = eval(pkt[1].command())            # generate a new packet from request packet
        replyPacket[ICMP].type = ReplyPacketInfo['type']# Change type to destined unreachable
        replyPacket[ICMP].code = ReplyPacketInfo['code']# Set code to  so that, it's
        replyPacket[IP].src = ReplyPacketInfo['src']
        replyPacket[IP].dst = ReplyPacketInfo['dst']
        replyPacket[IP].ttl = ReplyPacketInfo['ttl']
        del replyPacket[ICMP].chksum                    # Recalculate Checksum
        replyPacket.show2()
        print("Sending back:")
        sendp(replyPacket)



sniff(filter="icmp", prn=random_reject, store=0)
