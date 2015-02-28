__author__ = 'Yuxibro'
#!/usr/bin/python

from scapy.all import *

import os, sys
import socket
import fcntl

# About-face for a packet: swap src and dst in specified layer
def swap_src_and_dst(pkt, layer):
  pkt[layer].dst, pkt[layer].src = pkt[layer].src, pkt[layer].dst

# Constants needed to make a "magic" call to /dev/net/tun to create
#  a tap0 device that reads and writes raw Ethernet packets
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
TUNMODE = IFF_TAP
TUNSETOWNER = TUNSETIFF + 2

# Open TUN device file, create tap0
#
#  To open a new transient device, put "tap%d" into ioctl() below.
#   To open a persistent device, use "tap0" or the actual full name.
#
#  You can create a persistent device with "openvpn --mktun --dev tap0".
#   This device will show up on ifconfig, but will have "no link" unless
#   it is opened by this or similar script even if you bring it up with
#   "ifconfig tap0 up". This can be confusing.
#
#  Copied from https://gist.github.com/glacjay/585369
#   IFF_NO_PI is important! Otherwise, tap will add 4 extra bytes per packet,
#     and this will confuse Scapy parsing.
tun = os.open("/dev/net/tun", os.O_RDWR)

print "struct pack!: ",fcntl(tun, TUNSETIFF, struct.pack("16sH", "tap0", TUNMODE | IFF_NO_PI))

ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "tap0", TUNMODE | IFF_NO_PI))

ifname = ifs[:16].strip("\x00")  # will be tap0

# Optionally, we want tap0 be accessed by the normal user.
fcntl.ioctl(tun, TUNSETOWNER, 1000)

print "Allocated interface %s. Configuring it." % ifname

subprocess.check_call("ifconfig %s down" % ifname, shell=True)
subprocess.check_call("ifconfig %s hw ether 12:67:7e:b7:6d:c8" % ifname, shell=True)
subprocess.check_call("ifconfig %s 10.5.0.1 netmask 255.255.255.0 broadcast 10.5.0.255 up" % ifname, shell=True)

#
#  Now process packets
#
while 1:
  binary_packet = os.read(tun, 2048)   # get packet routed to our "network"
  packet = Ether(binary_packet)        # Scapy parses byte string into its packet object

  if packet.haslayer(ICMP) and packet[ICMP].type == 8 : # ICMP echo-request
    pong = packet.copy()
    swap_src_and_dst(pong, Ether)
    swap_src_and_dst(pong, IP)
    pong[ICMP].type='echo-reply'
    pong[ICMP].chksum = None   # force recalculation
    pong[IP].chksum   = None
    os.write(tun, pong.build())  # send back to the kernel

  elif packet.haslayer(ARP) and packet[ARP].op == 1 : # ARP who-has
    arp_req = packet;  # don't need to copy, we'll make reply from scratch

    # make up a new MAC for every IP address, using the address' last octet
    s1, s2, s3, s4 = arp_req.pdst.split('.')
    fake_src_mac = "12:67:7e:b7:6d:" + ("%02x" % int(s4))

    # craft an ARP response
    arp_rpl = Ether(dst=arp_req.hwsrc, src=fake_src_mac)/ARP(op="is-at", psrc=arp_req.pdst, pdst="10.5.0.1", hwsrc=fake_src_mac, hwdst=arp_req.hwsrc)
    os.write(tun, arp_rpl.build() ) # send back to kernel

  else:      # just print the packet. Use "packet.summary()" for one-line summary
    print "Unknown packet: "
    print packet.show()