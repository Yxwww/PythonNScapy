__author__ = 'Yuxibro'
from scapy.all import conf,sendp,srp1,ICMP,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP,get_if_raw_hwaddr,random,send,RandMAC,TCP,sr,sr1
import random
# Define end host and TCP port range
host = "www.facebook.com"
portRange = [22,23,80,443,3389]
# Send SYN with random Src Port for each Dst port
for dstPort in portRange:
    srcPort = random.randint(1025,65534)
    resp = sr1(IP(dst=host)/TCP(sport=srcPort,dport=dstPort,flags="S"),timeout=1,verbose=0)
    if (str(type(resp)) == "<type 'NoneType'>"):
        print host + ":" + str(dstPort) + " is filtered (silently dropped)."
    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=host)/TCP(sport=srcPort,dport=dstPort,flags="R"),timeout=1,verbose=0)
            print host + ":" + str(dstPort) + " is open."
        elif (resp.getlayer(TCP).flags == 0x14):
            print host + ":" + str(dstPort) + " is closed."
    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print host + ":" + str(dstPort) + " is filtered (silently dropped)."



# My port scan script
#TODO: any port for any host ??????