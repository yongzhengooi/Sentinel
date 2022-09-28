import enum
from http.client import HTTP_PORT
from operator import contains, index
from turtle import home
from types import NoneType
import scapy.all as scapy
from Logging import *
from Alert import Alert
import re
import binascii


class Rule:
    def __init__(self, protocol, src_ip, src_port, dst_ip, dst_port):
        self.protocol = str(protocol).strip()
        self.src_ip = str(src_ip).strip()
        self.src_port = str(src_port).strip()
        self.dst_ip = str(dst_ip).strip()
        self.dst_port = str(dst_port).strip()
        self.host_IP = str(scapy.get_if_addr(scapy.conf.iface))
        self.telnet_IP = "127.0.0.1"
        self.SMTP_IP = "127.0.0.1"
        self.SQL_IP = "127.0.0.1"
        self.HTTP_IP = "127.0.0.1"
        self.HTTP_PORT = "443"

    def setupTelnet_serverIP(self, telnet_IP):
        self.telnet_IP = str(telnet_IP).strip()

    def setupSMTP_serverIP(self, SMTP_IP):
        self.SMTP_IP = str(SMTP_IP).strip()

    def setupSQL_serverIP(self, SQL_IP):
        self.SQL_IP = str(SQL_IP).strip()

    def setupHTTP_serverIP(self, HTTP_IP, HTTP_PORT):
        self.HTTP_IP = str(HTTP_IP).strip()
        self.HTTP_PORT = str(HTTP_PORT).strip()

    def preCheking(packet):
        pass
    def checkRules(self, payload):
        #format the data to match the rule
        detail = "{} {} {} -> {} {} ".format(
            self.protocol, self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
        # try:
        with open("rules\\snort3-community.rules", "r") as file:
            ruleFile = file.readlines()
            for rule in ruleFile:
                symIndex=rule.index("(")
                ruleString=rule[6:symIndex]
                splitItem= ruleString.split(" ")
                #Filter the file variable 
                #As the format is fixed, can just loop with
                for i,item in enumerate(splitItem):
                    #SRC IP
                    if i == 1:
                        if (item=="$HOME_NET"):
                            splitItem[i]=self.host_IP
                        elif (item=="$HTTP_SERVERS"):
                            splitItem[i]=self.HTTP_IP
                        elif (item=="$SQL_SERVERS"):
                            splitItem[i]=self.SQL_IP
                        elif (item=="$TELNET_SERVERS"):
                            splitItem[i]=self.telnet_IP
                        elif (item=="$SMTP_SERVERS"):
                            splitItem[i]=self.SMTP_IP
                        else:
                            splitItem[i]=self.src_ip
                    #SRC IP
                    elif i==2:
                        if(item =="any"):
                            splitItem[i]=self.src_port
                        elif(item == "$HTTP_PORTS"):
                            splitItem[i]=self.HTTP_PORT
                    #Dst IP
                    elif i==4:
                        if (item=="$HOME_NET"):
                            splitItem[i]=self.host_IP
                        elif (item=="$HTTP_SERVERS"):
                            splitItem[i]=self.HTTP_IP
                        elif (item=="$SQL_SERVERS"):
                            splitItem[i]=self.SQL_IP
                        elif (item=="$TELNET_SERVERS"):
                            splitItem[i]=self.telnet_IP
                        elif (item=="$SMTP_SERVERS"):
                            splitItem[i]=self.SMTP_IP
                        else:
                            splitItem[i]=self.dst_ip
                    #DST PORT
                    elif i==5:
                        if(item =="any"):
                            splitItem[i]=self.dst_port
                        elif(item == "$HTTP_PORTS"):
                            splitItem[i]=self.HTTP_PORT
                newRule=" ".join(splitItem)
                if re.search(detail,newRule):
                    # Get the rule, remove execessive quote
                    print(rule)
                    ruleDict = self.getRuleDict(rule)
                    self.checkPayloadContent(ruleDict, payload)  
        # except Exception as e:
        #     Logging.logException(str(e))

    def getRuleDict(self, rule):
        if (len(rule)) > 0:
            ruleDict = {}
            if rule is not None:
                detail = None
                rule = rule.replace(")", "")
                index = rule.index("msg")
                detail = rule[index:].split("; ")
                detail.pop() 
                contentCount=1
                for item in detail:
                    if ":" in item:
                        current = item.split(":")
                        ruleDict.update({current[0]: str(current[1]).strip('"')})
                        if current[0]=="content":
                            contentCount+=1
                        elif contentCount >  1 and current[0]=="content":
                            ruleDict.update({"{}-{}".format(current[0],contentCount): str(current[1]).strip('"')})
                    else:
                        ruleDict.update({item: item})
        
            print(ruleDict)
            return ruleDict

    def checkPayloadContent(self, ruleDict, payload):
        # print(payload)
        if payload is not None:
            # pLen = len(payload)
            # converted_payload=binascii.hexlify(bytes(payload)," ").upper()
            if "content" in ruleDict:
                c=ruleDict.get("content")
                content = c.strip('"').replace('"', "").replace("|"," ")
                splitObj = content.split(",")
                content=splitObj[0]
                for ob in splitObj:
                    print(ob)
                    if "nocase" in ob:
                        # nocase=True
                        # contentRule =str(contentRule).upper()
                        # payload =str(payload).upper()
                        pass
                    if "depth" in ob:
                        depth=int(ob.split(" ")[1])
                        payload=str(payload[:depth])
                    if "distance" in splitObj:
                        distance=int(ob.split(" ")[1])
                        payload=str(payload[distance:])
                    if "offset" in splitObj:
                        offset=int(ob.split(" ")[1])
                        payload=str(payload[offset:])

            # If match with signature Alert
                if "[" in content:
                    content=str(content).replace("[","\[")
                else:
                    content=content.strip()
                if re.search(re.escape(content), payload):
                    Alert(
                        ruleDict.get("classtype"), ruleDict.get("msg")
                    ).generateDesktopNotification()
