from http.client import HTTP_PORT
from types import NoneType
import scapy.all as scapy


class Rule:
    def __init__(self, protocol, src_ip, src_port, dst_ip, dst_port):
        self.protocol = str(protocol)
        self.src_ip = str(src_ip)
        self.src_port = str(src_port)
        self.dst_ip = str(dst_ip)
        self.dst_port = str(dst_port)
        self.host_IP = str(scapy.get_if_addr(scapy.conf.iface))
        self.telnet_IP = "127.0.0.1"
        self.SMTP_IP = "127.0.0.1"
        self.SQL_IP = "127.0.0.1"
        self.HTTP_IP = "127.0.0.1"
        self.HTTP_PORT = "80"

    def setupTelnet_serverIP(self, telnet_IP):
        self.telnet_IP = str(telnet_IP)

    def setupSMTP_serverIP(self, SMTP_IP):
        self.SMTP_IP = str(SMTP_IP)

    def setupSQL_serverIP(self, SQL_IP):
        self.SQL_IP = str(SQL_IP)

    def setupHTTP_serverIP(self, HTTP_IP, HTTP_PORT):
        self.HTTP_IP = str(HTTP_IP)
        self.HTTP_PORT = str(HTTP_PORT)

    def checkRules(self):
        detail = "{} {} {} -> {} {}".format(
            self.protocol, self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
        with open("rules\\snort3-community.rules", "r") as file:
            ruleFile = file.readlines()
            for rule in ruleFile:
                # need refactor
                # check
                if "$HOME_NET" in rule and "$EXTERNAL_NET" in rule:
                    homeIndex = rule.index("$HOME_NET")
                    externalIndex = rule.index("$EXTERNAL_NET")
                    if homeIndex < externalIndex:
                        rule = (
                            rule.replace("$HOME_NET", self.host_IP)
                            .replace("$EXTERNAL_NET", self.dst_ip)
                            .replace("any", self.src_port, 1)
                            .replace("any", self.dst_port, 1)
                            .replace("$HTTP_PORTS", self.HTTP_PORT)
                        )
                    else:
                        rule = (
                            rule.replace("$HOME_NET", self.host_IP)
                            .replace("$EXTERNAL_NET", self.src_ip)
                            .replace("any", self.dst_port, 1)
                            .replace("any", self.src_port, 1)
                            .replace("$HTTP_PORTS", self.HTTP_PORT)
                        )
                elif "$EXTERNAL_NET" in rule and "$HTTP_SERVERS" in rule:
                    httpIndex = rule.index("$HTTP_SERVERS")
                    externalIndex = rule.index("$EXTERNAL_NET")
                    if httpIndex < externalIndex:
                        rule = (
                            rule.replace("$EXTERNAL_NET", self.src_ip)
                            .replace("$HTTP_SERVERS", self.HTTP_IP)
                            .replace("$HTTP_PORTS", self.HTTP_PORT)
                        )
                    else:
                        rule = (
                            rule.replace("$EXTERNAL_NET", self.dst_ip)
                            .replace("$HTTP_SERVERS", self.HTTP_IP)
                            .replace("$HTTP_PORTS", self.HTTP_PORT)
                        )
                elif "$EXTERNAL_NET" in rule and "$SMTP_SERVERS" in rule:
                    smtpIndex = rule.index("$SMTP_SERVERS")
                    externalIndex = rule.index("$EXTERNAL_NET")
                    if smtpIndex < externalIndex:
                        rule = rule.replace("$EXTERNAL_NET", self.src_ip).replace(
                            "$SMTP_SERVERS", self.SMTP_IP
                        )
                    else:
                        rule = rule.replace("$EXTERNAL_NET", self.dst_ip).replace(
                            "$SMTP_SERVERS", self.SMTP_IP
                        )
                elif "$EXTERNAL_NET" in rule and "$TELNET_SERVERS" in rule:
                    telnetIndex = rule.index("$TELNET_SERVERS")
                    externalIndex = rule.index("$EXTERNAL_NET")
                    if telnetIndex < externalIndex:
                        rule = rule.replace("$EXTERNAL_NET", self.src_ip).replace(
                            "$TELNET_SERVERS", self.telnet_IP
                        )
                    else:
                        rule = rule.replace("$EXTERNAL_NET", self.dst_ip).replace(
                            "$TELNET_SERVERS", self.telnet_IP
                        )
                elif "$EXTERNAL_NET" in rule and "$SQL_SERVERS" in rule:
                    sqlIndex = rule.index("$SQL_SERVERS")
                    externalIndex = rule.index("$EXTERNAL_NET")
                    if sqlIndex < externalIndex:
                        rule = rule.replace("$EXTERNAL_NET", self.src_ip).replace(
                            "$SQL_SERVERS", self.SQL_IP
                        )
                    else:
                        rule = rule.replace("$EXTERNAL_NET", self.dst_ip).replace(
                            "$SQL_SERVERS", self.SQL_IP
                        )
                else:
                    anyIndex = []
                    splitItem = rule.split()
                    sub = "any"
                    count = 0
                    for string in splitItem:
                        if string == "any":
                            anyIndex.append(rule.find(sub, rule.find(sub), count))
                            count += 1
                    if count == 2:
                        if anyIndex[0] < anyIndex[1]:
                            rule = rule.replace("any", self.src_ip, 1).replace(
                                "any", self.dst_ip, 1
                            )
                        else:
                            rule = rule.replace("any", self.dst_ip, 1).replace(
                                "any", self.src_ip, 1
                            )
                    elif count == 3:
                        if anyIndex[0] < anyIndex[1] and anyIndex[0] < anyIndex[2]:
                            rule = (
                                rule.replace("any", self.src_ip, 1)
                                .replace("any", self.src_port, 1)
                                .replace("any", self.dst_ip)
                            )

                if detail in rule:
                    # Filter the contain to prevent condition when port 88 show port 88 and 8888
                    index = rule.index("(")
                    filterRule = rule[6:index].strip()
                    if detail == filterRule:
                        print(rule)
                        self.getRuleDict(rule)

    def getRuleDict(self, rule):
        if (len(rule)) > 0:
            ruleDict = {}
            if rule is not None:
                detail = None
                rule = rule.replace(")", "")
                index = rule.index("msg")
                detail = rule[index:].split("; ")
                detail.pop()
                for item in detail:
                    if ":" in item:
                        current = item.split(":")
                        ruleDict.update({current[0]: current[1]})
                    else:
                        ruleDict.update({item: ""})
            return ruleDict
