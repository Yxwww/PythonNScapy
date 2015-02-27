__author__ = 'Yuxibro'

import logging
#import socket
logging.getLogger("scapy").setLevel(1)
from scapy.all import conf,sendp,srp1,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr
fam,hw = get_if_raw_hwaddr(conf.iface)


#sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover")]),count=1)
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type",1)]),count=1)