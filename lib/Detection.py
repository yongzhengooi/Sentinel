from unittest.mock import patch
from lib import *
from operator import concat, indexOf, mod
from os import stat
from datetime import datetime
import pyshark
from nfstream import NFStreamer, NFPlugin
import scapy.all as scapy
import shutil
import numpy as np
import asyncio
import threading
import re
from multiprocessing import Process
from lib.Rule import *
from lib.Learning import *
from lib.Alert import *
from lib.Logging import *
# from Rule import *
# from Learning import *
# from Alert import *
# from Logging import *
import pandas as pd
import binascii

latestIndex = 1
previousContentSize = 0


class Detection:
    def __init__(self) -> None:
        pass

    def generateCicFLowData():
        today = str(datetime.date.today().strftime("%Y-%m-%d"))
        command="start cmd /c cd \\data & cicflowmeter -i Wi-Fi -c {}.csv".format(today)
        print("Start generate flow")
        os.system(command)

    def starSniffing(interface="Wi-Fi"):
        today = str(datetime.date.today().strftime("%Y-%m-%d"))
        counter = 0
        capture = pyshark.LiveCapture(
            interface,
            output_file="data\\{}.pcap".format(today),
        )
        for packet in capture:
            if "IP" in packet:
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                Rule.checkBannedIP(src_ip, dst_ip)
                # print(packet)
                if packet.transport_layer == "TCP":
                    src_port = packet["TCP"].srcport
                    dst_port = packet["TCP"].dstport
                    print("{} {} -> {} {} ".format(src_ip, src_port, dst_ip, dst_port))
                    if "segment_data" in dir(packet["TCP"]):
                        payload = packet["TCP"].segment_data
                        payload = str(payload).replace(":", " ")
                        # print(payload)
                        Rule("tcp", src_ip, src_port, dst_ip, dst_port).checkRules(
                            payload
                        )
                if packet.transport_layer == "UDP":
                    if "segment_data" in dir(packet["UDP"]):
                        payload = packet["UDP"].segment_data
                        payload = str(payload).replace(":", " ")
                        Rule("udp", src_ip, src_port, dst_ip, dst_port).checkRules(
                            payload
                        )
            counter += 1
            if counter == 100:
                Detection.prediction()
                counter = 0
    
    def prediction(algo="knn",classes=Learning().x_train,threshold=30):
        type_bruteforce = ["FTP-BruteForce", "SSH-Bruteforce"]
        type_dos = [
            "DoS attacks-GoldenEye",
            "DoS attacks-Slowloris",
            "DoS attacks-SlowHTTPTest",
            "DoS attacks-Hulk",
        ]
        type_ddos = [
            "DDoS attacks-LOIC-HTTP",
            "DDOS attack-LOIC-UDP",
            "DDOS attack-HOIC",
        ]
        type_webBased = ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]
        type_others = ["Infilteration", "Bot"]
        # get value from textfile ,proccessing and save to dataframe
        today = str(datetime.date.today().strftime("%Y-%m-%d"))
        content = []
        try:
            with open("data\\cic_{}.txt".format(today), "r") as file:
                var = file.readlines()
                for pac in var:
                    pac = (
                        pac.replace("dict_keys([", "")
                        .replace("dict_values([", "")
                        .replace("])", "")
                        .replace("'", "")
                        .replace(" ", "")
                        .replace("\n", "")
                        .split(",")
                    )
                    content.append(pac)
        except FileNotFoundError:
            Logging.logException("cic_{}.txt not found".format(today))
            return
        global latestIndex
        global previousContentSize
        previousCheck = False
        if len(content) > previousContentSize:
            previousContentSize = len(content)
            previousCheck = True
        if len(content) > 1 and previousCheck:
            df = pd.DataFrame(content)
            df.columns = df.iloc[0]
            toDropList = [
                "src_ip",
                "dst_ip",
                "src_port",
                "timestamp",
                "src_mac",
                "dst_mac",
            ]
            df.drop(toDropList, inplace=True, axis=1)
            df = df[latestIndex:]
            # filter out the best 11 feature
            bestFeature = [
                "dst_port",
                "fwd_seg_size_min",
                "fwd_pkt_len_mean",
                "fwd_seg_size_avg",
                "fwd_pkt_len_std",
                "init_bwd_win_byts",
                "fwd_pkt_len_max",
                "pkt_size_avg",
                "pkt_len_mean",
                "bwd_pkt_len_min",
                "pkt_len_min",
                ]
            selectedDf = df[bestFeature]
            allpacket = []

            le = LabelEncoder()
            encoded = le.fit(
                [
                    "Benign",
                    "FTP-BruteForce",
                    "SSH-Bruteforce",
                    "DoS attacks-GoldenEye",
                    "DoS attacks-Slowloris",
                    "DoS attacks-SlowHTTPTest",
                    "DoS attacks-Hulk",
                    "DDoS attacks-LOIC-HTTP",
                    "DDOS attack-LOIC-UDP",
                    "DDOS attack-HOIC",
                    "Brute Force -Web",
                    "Brute Force -XSS",
                    "SQL Injection",
                    "Infilteration",
                    "Bot",
                ]
            )
            for index, feature in selectedDf.iterrows():
                allpacket.append(
                            [float(feature[0]),
                            float(feature[1]),
                            float(feature[2]),
                            float(feature[3]),
                            float(feature[4]),
                            float(feature[5]),
                            float(feature[6]),
                            float(feature[7]),
                            float(feature[8]),
                            float(feature[9]),
                            float(feature[10])]
                    )
            try: 
                if allpacket is not None:
                    if len(allpacket) >1:
                        prediction, prob = Learning().predictLabel(
                            # np.array(allpacket).reshape(1,-1), selection=algo
                            classes,np.array(allpacket),selection=algo
                        )
                        latestIndex = previousContentSize
                        # generate alert based on prediction
                        newProb = []
                        for item in prob:
                            newProb.append(round(max(item) * 100, 2))
                        checkingType = zip(encoded.inverse_transform(prediction), newProb)

                        currentDDOS_count=0
                        for label, probability in checkingType:
                            if float(probability) >= threshold:
                                if label in type_bruteforce:
                                    Alert(
                                        "Bruteforce type attemped",
                                        # "Source: {} Dst: {} Port: {}".format(src_ip, dst_ip, dst_port),
                                        "{} Detected \n Probability of predicted attack :{}".format(
                                            label, probability
                                        ),
                                    ).generateDesktopNotification()
                                elif label in type_dos or label in type_ddos:
                                    if currentDDOS_count > 5 or currentDDOS_count==0:
                                        Alert(
                                            "Dos/DDOS type attemped",
                                            # "Source: {} Dst: {}Port: {}".format(src_ip, dst_ip, dst_port),
                                            "{} Detected \n Probability of predicted attack :{}".format(
                                                label, probability
                                            ),
                                        ).generateDesktopNotification()
                                    currentDDOS_count+=1
                                elif label in type_webBased:
                                    Alert(
                                        "Web attack type attemped",
                                        # "Source: {} Dst: {}Port: {}".format(src_ip, dst_ip, dst_port),
                                        "{} Detected \n Probability of predicted attack :{}".format(
                                            label, probability
                                        ),
                                    ).generateDesktopNotification()
                                elif label in type_others:
                                    Alert(
                                        "Type others attemped",
                                        # "Source: {} Dst: {}Port: {}".format(src_ip, dst_ip, dst_port),
                                        "{} Detected \n Probability of predicted attack :{}".format(
                                            label, probability
                                        ),
                                    ).generateDesktopNotification()
                        return [encoded.inverse_transform(prediction),newProb]
            except Exception as e:
                Logging.logException(str(e))


# class PayloadCollector(NFPlugin):
#     @staticmethod
#     def _extend_flow_payload(packet, flow):
#         if packet.payload_size > 0:
#             payload = packet.ip_packet[-packet.payload_size :]
#             flow.udps.payload.extend(payload)

#     def on_init(self, packet, flow):
#         flow.udps.payload = bytearray()
#         self._extend_flow_payload(packet, flow)

#     def on_update(self, packet, flow):
#         self._extend_flow_payload(packet, flow)


p = "7C 30 44 20 30 41 7C 55 73 65 72 2D 41 67 65 6E 74 7C 33 41 7C 20 4A 61 76 61 2F"
p3 = "137A18"
p2 = "2E 63 6C 61 73 73 0D 0A 75 73 65 72 2D 61 67 65 6E 74 3A 20 6A 61 76 61 2F"
# Rule("tcp", "190.144.160", "12",str(scapy.get_if_addr(scapy.conf.iface)) , "79").checkRules(p.replace(" ",""))
# Rule("tcp", str(scapy.get_if_addr(scapy.conf.iface)), "2589","190.144.160" , "80").checkRules(p2)
# Rule("tcp", "12.41.211.1","2589","127.0.0.1" , "25").checkRules(p2)
    
