import enum
from http.client import HTTP_PORT
from operator import contains, index
from turtle import home
from types import NoneType
import scapy.all as scapy
from Logging import *
from Alert import Alert
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

    def preCheking(packet):
        pass

    def indexingRules(regex):
        fullruleStr = ""
        with open("rules\\snort3-community.rules", "r") as file:
            ruleFile=file.read()
            return re.findall("{} \w+".format(regex),ruleFile)
            
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
        
            if "content-1" in ruleDict:
                print(ruleDict)
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
            for i in range(1,4):
                decodeContent=""
                decodePayload=""
                if "content-{}".format(i) in ruleDict:
                    print("content-{}".format(i))
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
                                splitContent[index] =  byteDecode.decode("ASCII",errors="ignore")
                        decodePayload=bytes.fromhex(modPayload).decode("ASCII",errors="ignore")
                        decodeContent= "".join(splitContent)
                        if nocase:
                            decodeContent = decodeContent.lower()
                            decodePayload = decodePayload.lower()
                    except UnicodeDecodeError :
                        Logging.logException("Unable to decode the payload via ASCII")
                    except ValueError:
                        pass
                else:
                    continue
                    
            # if "content-1" in ruleDict:
            #     # modPayload = payload
            #     c=ruleDict.get("content-1")
            #     content = c.strip('"').replace('"', "")
            #     splitObj = content.split(",")
            #     content=splitObj[0]
            #     oricont=content
            #     # modPayload,nocase=self.getModifiedPayload(splitObj,payload)
            #     # decodeContent,decodePayload=self.getHelixyContentAndPayload(content,modPayload,nocase)
            #     for ob in splitObj:
            #         if "nocase" in ob:
            #             nocase=True
            #         if "depth" in ob:
            #             depth=re.findall('\d+',ob)
            #             modPayload=payload[:32*int(depth[0])]
            #         if "offset" in ob:
            #             offset=re.findall('\d+',ob)
            #             modPayload=payload[4*int(offset[0]):]
            #     if "content-2" in ruleDict:
            #         pass
            #     if len(content) >2:
            #         splitContent=content.split("|")
            #         decodeContent=""
            #         decodePayload=""
            #         # try decode for rule content with ascii
            #         try:
            #             for index,hex in enumerate(splitContent):
            #                 if Rule.checkHex(hex.replace(" ","")) and re.search("[0-9a-fA-F][0-9a-fA-F]",hex):
            #                     byteDecode=bytes.fromhex(hex)
            #                     splitContent[index] =  byteDecode.decode("ASCII",errors="ignore")
            #                 decodePayload=bytes.fromhex(modPayload).decode("ASCII",errors="ignore")
            #                 decodeContent= "".join(splitContent)
            #             if nocase:
            #                 decodeContent = decodeContent.lower()
            #                 decodePayload = decodePayload.lower()
            #         except UnicodeDecodeError :
            #             Logging.logException("Unable to decode the payload via ASCII")
            #         except ValueError:
            #             pass
            #         # print(decodeContent)
                # if re.search(r"[!@)(#?|$%^&\\*.]",decodeContent):
                    
                # else:
                #     decodeContent=str(binascii.hexlify(bytes(str(decodeContent),"ascii")),"ascii").replace(" ","")
                # converted_payload=binascii.hexlify(bytes(str(payload),"utf8"))
                decodeContent=str(binascii.hexlify(bytes(re.escape(decodeContent),"ascii")),"ascii").replace(" ","")
                decodePayload=str(binascii.hexlify(bytes(re.escape(decodePayload),"ascii")),"ascii").replace(" ","")
                print(decodeContent)
                print(decodePayload)
                if decodeContent in decodePayload and decodeContent != "":
                    # Alert(
                    #     ruleDict.get("classtype"), ruleDict.get("msg")
                    # ).generateDesktopNotification()
                    # Logging.logInfo("payload :{} \n content {}".format(payload,oricont))
                    if i == 1:
                        multipleContentCheck[i-1]=True
                    else:
                        multipleContentCheck.append(True)
                else:
                    multipleContentCheck.append(False)
                if "pcre" in ruleDict:
                    regex = ruleDict.get("pcre")
                    if re.search(r"[!@)(#?$%^&*.]",content):
                        escContent=re.escape(regex)
                        escpayload=re.escape(modPayload)
                        decodeMatchingPayload=str(binascii.hexlify(bytes(str(escpayload),"utf8")),"utf8").upper().replace(" ","")
                        if re.search(escContent,decodeMatchingPayload):
                            multipleContentCheck[i-1]=True
                            Alert(
                                ruleDict.get("classtype"), ruleDict.get("msg")
                            ).generateDesktopNotification()
                            Logging.logInfo("payload :{} \n content {}".format(payload,content))
            if False in multipleContentCheck:
                pass
            else:
                multipleContentCheck.clear()
                Alert(
                        ruleDict.get("classtype"), ruleDict.get("msg")
                    ).generateDesktopNotification()
                Logging.logInfo("payload :{} \n content {}".format(payload,oricont))

    def getModifiedPayload(self,splitObj,payload):
        modPayload = payload
        nocase=False
        for ob in splitObj:
            if "nocase" in ob:
                nocase=True
            if "depth" in ob:
                depth=re.findall('\d+',ob)
                modPayload=str(payload[:32*int(depth[0])]).replace(" ","")
            if "offset" in ob:
                offset=re.findall('\d+',ob)
                modPayload=str(payload[4*int(offset[0]):]).replace(" ","")
        return modPayload,nocase
    
    def getHelifyContentAndPayload(self,contentlist,modPayload,nocase=False):
        # try decode for rule content with ascii
        try:
            splitContent=contentlist.split("|")
            for index,hex in enumerate(splitContent):
                if Rule.checkHex(hex.replace(" ","")) and re.search("[0-9a-fA-F][0-9a-fA-F]",hex):
                    byteDecode=bytes.fromhex(hex)
                    splitContent[index] =  byteDecode.decode("ASCII",errors="ignore")
                decodePayload=bytes.fromhex(modPayload).decode("ASCII",errors="ignore")
            if splitContent != None:
                decodeContent= "".join(splitContent)
            else:
                decodeContent=contentlist
            if nocase:
                decodeContent = decodeContent.lower()
                decodePayload = decodePayload.lower()

            decodeContent=str(binascii.hexlify(bytes(re.escape(decodeContent),"utf8")),"utf8").replace(" ","")
            decodePayload=str(binascii.hexlify(bytes(re.escape(decodePayload),"utf8")),"utf8").replace(" ","")
            return decodeContent, decodePayload
        except UnicodeDecodeError :
            Logging.logException("Unable to decode the payload via ASCII")
        except ValueError:
            Logging.logException("Non hex value found")
        except TypeError:
            Logging.logException("Unable to decode the payload via ASCII")
        # print(decodeContent)
        
    def checkBannedIP(src,dst):
        with open("rules\\badIP.txt", "r") as file:
            banIP = file.readlines()
            for ip in banIP:
                if src == ip or dst == ip:
                    Alert("User prohibited traffic detected","Source : {} -> {} ".format(src,dst)).generateDesktopNotification()