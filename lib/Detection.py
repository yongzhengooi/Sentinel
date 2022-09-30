import http
from lib import *
from ipaddress import IPv4Interface
from operator import concat, indexOf, mod
from os import stat
import struct
from types import NoneType
from typing import Type
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.utils import hexdump
from Rule import *
from Alert import *
from Logging import *
import binascii


class Detection:
    def __init__(self) -> None:
        pass
    def getPacket(interface=scapy.get_if_addr(scapy.conf.iface)):
        scapy.sniff(store=False, prn=Detection.process_packet)
        # scapy.sniff(prn=Detection.process_packet)

    def packetSummary(packet):
        print(packet)

    def startOrStopSniffer(filterStatus=False):
        return filterStatus

    def process_packet(packet):
        if "IP" in packet:
            src_ip=packet["IP"].src
            dst_ip=packet["IP"].dst
            
            if "TCP" in packet:
                src_port=packet["TCP"].sport
                dst_port=packet["TCP"].dport
                if (packet["TCP"].payload is not None):
                    payload=bytes(packet["TCP"].payload)
                    if src_port == "80" or dst_port=="80":
                            pass
                        # print(payload)
                Logging.logInfo("{} {} -> {} {}".format(src_ip,src_port,dst_ip,dst_port))
                Rule("tcp",src_ip,src_port,dst_ip,dst_port).checkRules(payload)
                
            if "UDP" in packet:
                src_port=packet["UDP"].sport
                dst_port=packet["UDP"].dport
                payload=binascii.hexlify(bytes(packet["UDP"].payload)," ").upper()
                Rule("udp",src_ip,src_port,dst_ip,dst_port).checkRules(payload)
        # if packet.haslayer(HTTPRequest):
        #     url = packet["HTTPRequest"].Host.decode() + packet["HTTPRequest"].Path.decode()
        #     method = packet["HTTPRequest"].Method.decode()
        #     print("{} requested: {} [{}]".format(src_ip,url,method))
        #     Logging.logInfo("{} requested: {} [{}]".format(src_ip,url,method))
p="|00 AC D3 62 78 26 |00 00 00 00| 76 31 E5 E7 E5 1D C2 3C 15 40 25 2F 90 BD 1F 7F 0E 5E 33 77 EC 0C 1E 6B 61 47|"
p2="|24 7B|2|00 00 00 06 00 00 00|Drives|24 00| User3User32LogonProcesss2Logon|D0 CF 11 E0 A1 B1 1A E1|Processs"
Rule("tcp", "190.144.160", "12",str(scapy.get_if_addr(scapy.conf.iface)) , "79").checkRules(p.replace(" ",""))
Rule("tcp", str(scapy.get_if_addr(scapy.conf.iface)), "2589","190.144.160" , "80").checkRules(p2)
Rule("tcp", "12.41.211.1","2589","127.0.0.1" , "25").checkRules(p2)
# Detection.getPacket()