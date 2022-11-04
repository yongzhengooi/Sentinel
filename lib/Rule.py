import enum
from http.client import HTTP_PORT
from operator import contains, index
from turtle import home
from types import NoneType
import scapy.all as scapy
from lib.Logging import *
from lib.Alert import Alert
# from Logging import *
# from Alert import Alert
import re
import string
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
        self.HTTP_PORT = "80"

    def setupTelnet_serverIP(self, telnet_IP):
        self.telnet_IP = str(telnet_IP).strip()

    def setupSMTP_serverIP(self, SMTP_IP):
        self.SMTP_IP = str(SMTP_IP).strip()

    def setupSQL_serverIP(self, SQL_IP):
        self.SQL_IP = str(SQL_IP).strip()

    def setupHTTP_serverIP(self, HTTP_IP, HTTP_PORT):
        self.HTTP_IP = str(HTTP_IP).strip()
        self.HTTP_PORT = str(HTTP_PORT).strip()

            
    def checkRules(self, payload):
        #format the data to match the rule
        detail = "{} {} {} -> {} {} ".format(
            self.protocol, self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
        Logging.logInfo(detail)
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
                    #SRC PORT
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
                    # print(rule)
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
                        if current[0]=="content":
                            ruleDict.update({"{}-{}".format(current[0],contentCount): str(current[1]).strip('"')})
                            contentCount+=1
                        else:
                            ruleDict.update({current[0]: str(current[1]).strip('"')})
                    else:
                        ruleDict.update({item: item})
            return ruleDict

    def checkHex(hexString):
        for hexNum in hexString:
            if hexNum not in string.hexdigits:
                return False
        return True

    def checkPayloadContent(self, ruleDict, payload):
        regex = ""
        oricont=""
        nocase=False
        if payload is not None:
            multipleContentCheck = [False]
            for i in range(1,6):
                decodeContent=""
                decodePayload=""
                if "content-{}".format(i) in ruleDict:
                    modPayload=payload
                    c=ruleDict.get("content-{}".format(i))
                    content = c.strip('"').replace('"', "")
                    splitObj = content.split(",")
                    content=splitObj[0]
                    oricont=content
                    modPayload,nocase=self.getModifiedPayload(splitObj,payload)
                    # decodeContent,decodePayload=self.getHelifyContentAndPayload(content,modPayload,nocase)
                    splitContent=content.split("|")
                    decodeContent=""
                    decodePayload=""
                    # try decode for rule content with ascii
                    try:
                        for index,hex in enumerate(splitContent):
                            if Rule.checkHex(hex.replace(" ","")) and re.search("[0-9a-fA-F][0-9a-fA-F]",hex):
                                byteDecode=bytes.fromhex(hex)
                                splitContent[index] =  byteDecode.decode("ASCII")
                        decodePayload=bytes.fromhex(modPayload).decode("ASCII",errors="ignore")
                        decodeContent= "".join(splitContent)
                        if nocase:
                            decodeContent = decodeContent.lower()
                            decodePayload = decodePayload.lower()
                    except UnicodeDecodeError :
                        pass
                    except ValueError:
                        pass
                else:
                    continue

                decodeContent=str(binascii.hexlify(bytes(re.escape(decodeContent),"utf8")),"utf8").replace(" ","")
                decodePayload=str(binascii.hexlify(bytes(re.escape(decodePayload),"utf8")),"utf8").replace(" ","")
                # if "flow" in ruleDict:
                #     flow=ruleDict.get("flow")
                #     if flow in decodeContent:
                #         if i == 1:
                #             multipleContentCheck[i-1]=True
                #         else:
                #             multipleContentCheck.append(True)
                #     else:
                #         multipleContentCheck.append(False)

                if decodeContent in decodePayload and decodeContent != "":
                    if i == 1:
                        multipleContentCheck[i-1]=True
                    else:
                        multipleContentCheck.append(True)
                else:
                    multipleContentCheck.append(False)
            if False in multipleContentCheck:
                pass
            else:
                if "pcre" in ruleDict:
                    regex = ruleDict.get("pcre")
                    if re.search(r"[!@)(#?$%^&*.]",content):
                        escContent=re.compile(regex)
                        escpayload=re.escape(modPayload)
                        # decodeMatchingPayload=str(binascii.hexlify(bytes(str(escpayload),"utf8")),"utf8").replace(" ","")
                        if re.search(escContent,escpayload):
                            Alert(
                                ruleDict.get("classtype"), ruleDict.get("msg")
                            ).generateDesktopNotification()
                            Logging.logInfo("payload :{} \n content {}".format(payload,content))
                else:
                    Alert(
                            ruleDict.get("classtype"), ruleDict.get("msg")
                        ).generateDesktopNotification()
                    Logging.logInfo("payload :{} \n content {}".format(payload,oricont))
                    multipleContentCheck.clear()
                    return [self.src_ip,self.src_port,self.dst_ip,self.dst_port,ruleDict.get("classtype"), ruleDict.get("msg")]

    def getModifiedPayload(self,splitObj,payload):
        modPayload = payload
        nocase=False
        for ob in splitObj:
            if "nocase" in ob:
                nocase=True
            if "depth" in ob:
                depth=re.findall('\d+',ob)
                modPayload=str(payload[:2*int(depth[0])]).replace(" ","")
            if "offset" in ob:
                offset=re.findall('\d+',ob)
                modPayload=str(payload[2*int(offset[0]):]).replace(" ","")
        return modPayload,nocase
    
    def checkBannedIP(src,dst):
        with open("rules\\badIP.txt", "r") as file:
            banIP = file.readlines()
            for ip in banIP:
                if src == ip or dst == ip:
                    Alert("Bad traffic detected","Source : {} -> {} ".format(src,dst)).generateDesktopNotification()

    def checkUserBanIP(protocol,src,srcport,dst,dstport):
        with open("miscellaneous\\userDefineRule.txt", "r") as file:
            defineIP = file.readlines()
            for item in defineIP:
                splitItem=item.split(",")
                if "any" in splitItem[2]:
                    itemStr=f"{protocol},{src},any,{dst},{dstport}"
                elif "any" in splitItem[4]:
                    itemStr=f"{protocol},{src},{srcport},{dst},{dstport}"
                elif "any" in splitItem[2] and "any" in splitItem[4]:
                    itemStr=f"{protocol},{src},any,{dst},any"
                else:
                    itemStr=f"{protocol},{src},{srcport},{dst},{dstport}"
                if re.match(item.replace("\n",""),itemStr):
                    Alert("User prohibited traffic detected","Source : {} -> {} ".format(src,dst)).generateDesktopNotification()
                    
                