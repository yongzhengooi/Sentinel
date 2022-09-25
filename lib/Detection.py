import http
from ipaddress import IPv4Interface
from operator import concat, indexOf, mod
from os import stat
import socket
import struct
from types import NoneType
from typing import Type
import scapy.all as scapy
from scapy.layers import http
from Rule import Rule


class Detection:
    def getPacket(interface=scapy.get_if_addr(scapy.conf.iface)):
        scapy.sniff(filter=interface, store=False, prn=Detection.process_packet)

    def process_packet(pck):
        print(pck.show())

    def getCurrentIP():
        return scapy.get_if_addr(scapy.conf.iface)

    

Rule("udp", "192.168.1.28", "12", "135.123.12", "69").checkRules()

