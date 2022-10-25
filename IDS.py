from ast import main
from asyncio.subprocess import Process
from ctypes import windll
from distutils.command.build import build
from multiprocessing import process
from multiprocessing.sharedctypes import Value
from operator import indexOf
import ipaddress
from os import scandir
from signal import Signals
from unittest.util import sorted_list_difference
from PyQt5.QtGui import *
import threading
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import re
import nest_asyncio
from PyQt5.uic import loadUi
from PyQt5.QtWebSockets import *
from datetime import datetime
import asyncio

import threading
from asyncqt import QEventLoop
from scapy.all import *
from scapy import *
import matplotlib
import pyshark
import multiprocessing
from lib import *
from lib.Alert import Alert
from lib.Detection import Detection
from lib.Logging import Logging
from lib.Rule import Rule
from ui.design import Ui_MainWindow
class Worker(QRunnable):
    pass

class IDS_Window(QMainWindow):
    def __init__(self):
        super().__init__()
        #Variable init
        self.slicer_value=0
        self.Detection_range=0
        self.algoIndex=0
        self.boot=0
        # loadUi("design.ui",self)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("Sentinel")
        self.trigger=True
        self.initConfiguration()
        # get data for listview
        self.collectedRule=[]
        self.emailList=[]
        self.thread={}
        #Startup the sniffer
        # Menu listView (Changing page)
        self.ui.stackedWidget.setCurrentIndex(0)
        self.ui.menu_listView.item(0).setSelected(True)
        self.ui.menu_listView.clicked.connect(self.change_page)

        #Dashboard
        self.ui.livePacket_textBrowser

        #Rule page
        self.model=QStandardItemModel()
        self.ui.rules_listView.setModel(self.model)
        self.ui.addRules_button.clicked.connect(self.addRule)
        self.ui.searchRulesIP_editText.textChanged.connect(self.searchRule)
        self.getData()

        #Setting page
        #slicer
        self.ui.detectionLevel_slicer.setMinimum(30)
        self.ui.detectionLevel_slicer.setMaximum(100)
        self.ui.detectionLevel_slicer.setValue(self.slicer_value)
        self.ui.detectionLevel_slicer.sliderReleased.connect(self.slicerChange)

        #detect range
        if self.Detection_range == 0:
            self.ui.detection_rangeOnly_radioButton.setChecked(True)
        else:
            self.ui.detection_entireNetwork_radioButton.setChecked(True)
        #setup email recepient
        self.ui.addEmail_button.clicked.connect(self.addEmail)
        #algorithm combo box
        algorithm=["randomForest","adaboost","decisionTree","knn","naiveBayes"]
        self.ui.algorithms_comboBox.addItems(algorithm)
        self.ui.algorithms_comboBox.setCurrentIndex(self.algoIndex)

    def initConfiguration(self):
        if not os.path.exists("miscellaneous\\configuration.txt"):
            initString="slicer_value = 100\nDetection_range=0\nalgo=3\nboot=0"
            with open("miscellaneous\\configuration.txt", "a") as file:
                    file.write(initString)
                    file.close()
        else:
            with open("miscellaneous\\configuration.txt", "r") as file:
                var = file.readlines()
                for item in var:
                    splited=item.replace("\n","").strip().split("=")
                    if "slicer_value" in splited[0]:
                        self.slicer_value=int(splited[1])
                    elif "Detection_range" in splited[0]:
                        self.Detection_range=int(splited[1])
                    elif "algo" in splited[0]:
                        self.algoIndex=int(splited[1])
                    elif "boot" in splited[0]:
                        self.boot=int(splited[1])
                file.close()
    #For listview
    def change_page(self):
        selectedPage = self.ui.menu_listView.currentItem().text()
        if selectedPage == "Dashboard":
            self.ui.stackedWidget.setCurrentIndex(0)
        elif selectedPage == "Event":
            self.ui.stackedWidget.setCurrentIndex(1)
        elif selectedPage == "Rules":
            self.ui.stackedWidget.setCurrentIndex(2)
        elif selectedPage == "Setting":
            self.ui.stackedWidget.setCurrentIndex(3)
        elif selectedPage == "Export":
            self.ui.stackedWidget.setCurrentIndex(4)
        elif selectedPage == "Switch":
            if self.trigger:
                # print("Sniffer starting")
                self.thread[1] = sniffThread(parent=None)
                self.thread[1].start()
                self.thread[1].sig.connect(self.updateLivePacket)
                self.trigger = False
            else:
                print("stop")
                self.thread[1].stop()
                self.trigger = True
    def createSniffer(self):
        loop= asyncio.new_event_loop()
        nest_asyncio.apply(loop=loop)
        asyncio.set_event_loop(loop=loop)
        Thread(loop.run_forever(self.sniffing())).start()
        asyncio.create_task(self.sniffing())
    #For rule
    def addRule(self):
        def checkValidIP(ipString):
            try:
                ipaddress.ip_network(ipString)
            except:
                return False
            return True

        def checkValidPort(portString):
            try:
                if int(portString) >= 0 and int(portString) <=65535:
                    return True
                else:
                    return False
            except ValueError:
                return False
        ruleType=str(self.ui.packetType_comboBox.currentText())
        srcIP=self.ui.add_srcIP_editText.toPlainText()
        srcPort=self.ui.add_srcPort_editText.toPlainText()
        dstIP=self.ui.add_dstIP_editText.toPlainText()
        dstPort=self.ui.add_dstPort_editText.toPlainText()
        
        #Check ip and port 
        if checkValidIP(srcIP) and checkValidIP(dstIP):
            if checkValidPort(srcPort) and checkValidPort(dstPort):
                rule = "alert {} {} {} -> {} {}".format(ruleType,srcIP,srcPort,dstIP,dstPort)
                self.collectedRule.append(rule)
                self.model.clear()
                for i in self.collectedRule:
                    self.model.appendRow(QStandardItem(i))
                if not os.path.exists("miscellaneous\\userDefineRule.txt"):
                    with open("miscellaneous\\userDefineRule.txt","w") as file:
                        file.write(rule)
                        file.close()
                else:
                    with open("miscellaneous\\userDefineRule.txt","a") as file:
                        file.write("\n{}".format(rule))
                        file.close()

                #Clear field
                self.ui.add_srcIP_editText.setPlainText("")
                self.ui.add_srcPort_editText.setPlainText("")
                self.ui.add_dstIP_editText.setPlainText("")
                self.ui.add_dstPort_editText.setPlainText("")
            else:
                Alert("Unknow network port ","Please make sure the port is within range 0-65535").generateDesktopNotification(thread=True)
        else:
            Alert("Unknow IP address","Please make sure the ip format is correct").generateDesktopNotification(thread=True)
    
    def getData(self):
        try:
            with open("miscellaneous\\userDefineRule.txt","r") as file:
                data = file.readlines()
                for item in data:
                    self.collectedRule.append(item.replace("\n",""))
                file.close
                for i in self.collectedRule:
                    self.model.appendRow(QStandardItem(i))
            with open("miscellaneous\\email.txt") as file:
                emailItem=file.readlines()
                for item in emailItem:
                    self.emailList.append(item.replace("\n",""))
                file.close
        except FileNotFoundError:
            Logging.logException(FileNotFoundError)


            
    def searchRule(self):
        searchIP=self.ui.searchRulesIP_editText.toPlainText()
        searchPort=self.ui.searchRulesPort_editText.toPlainText()
        filterModel=QSortFilterProxyModel()
        obtainedIP = self.model.findItems(searchIP)
        obtainedPort = self.model.findItems(searchPort)
        if len(obtainedIP) > 0:
            for item in obtainedIP:
                if searchIP:
                    self.model.takeRow(item.row()) #take row of item
                    self.model.insertRow(0, item) 
        if len(obtainedPort)>0:
            pass

    #For setting
    def slicerChange(self):
        value = self.ui.detectionLevel_slicer.value()
        self.changeVariableOnTxt("slicer_value = {}".format(self.slicer_value),"slicer_value = {}".format(value))

    def changeVariableOnTxt(self,ori,replace):
        with open("miscellaneous\\configuration.txt", "r") as file:
            data=file.read()
            data=data.replace(ori,replace)
            file.close()
        with open("miscellaneous\\configuration.txt", "w") as file:
            file.write(data)
            file.close()


    def addEmail(self):
        email= self.ui.email_editText.toPlainText()
        emailPattern = "[\w.]+\@[\w.]+"
        if re.search(emailPattern, email):
            if not os.path.exists("miscellaneous\\email.txt"):
                with open("miscellaneous\\email.txt","w") as file:
                    file.write(email)
                    file.close()
            else:
                with open("miscellaneous\\email.txt","a") as file:
                    file.write("\n{}".format(email))
                    file.close()
            Alert("Successfully saved the email","").generateDesktopNotification(thread=True)
            Alert("Welcome to sentinel","You has been added to received notification email from sentinel, any threat will be notify to you via email and notification").sendEmail(personalEmail=email)
            self.ui.email_editText.setPlainText("")
        else:
            Alert("Invalid email format","Please enter valid email").generateDesktopNotification(thread=True)
            self.ui.email_editText.setPlainText("")

        
        
    def updateLivePacket(self,ip):
        self.ui.livePacket_textBrowser.append(ip)

class sniffThread(QThread):
    sig = pyqtSignal(str)
    def __init__(self,parent=None):
        super(sniffThread,self).__init__(parent)
        self.is_running = True

    def run(self):
        loop= asyncio.new_event_loop()
        nest_asyncio.apply(loop=loop)
        asyncio.set_event_loop(loop=loop)
        Thread(loop.run_forever(self.testSniffing())).start()
        asyncio.create_task(self.testSniffing())

    def testSniffing(self):
        print("Sniffer starting")
        today = str(datetime.today().strftime("%Y-%m-%d"))
        counter = 0
        capture = pyshark.LiveCapture(
            "Wi-Fi",
            output_file="data\\{}.pcap".format(today),
        )
        for packet in capture:
            if "IP" in packet:
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                Rule.checkBannedIP(src_ip, dst_ip)
                if packet.transport_layer == "TCP":
                    src_port = packet["TCP"].srcport
                    dst_port = packet["TCP"].dstport
                    # print("{} {} -> {} {} ".format(src_ip, src_port, dst_ip, dst_port))
                    self.sig.emit("{} {} -> {} {} ".format(src_ip, src_port, dst_ip, dst_port))
                    if "segment_data" in dir(packet["TCP"]):
                        payload = packet["TCP"].segment_data
                        payload = str(payload).replace(":", " ")
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
    #
    def stop(self):
        self.is_running=False
        self.terminate()


if __name__ == "__main__":
    app = QApplication([])
    window = IDS_Window()
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    with open("ui\\SyNet.qss", "r") as file:
        window.setStyleSheet(file.read())
    window.show()
    app.exec()
