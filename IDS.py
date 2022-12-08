from asyncio.subprocess import Process
from ctypes import windll
from distutils.command.build import build
from errno import WSAEDQUOT
from lib2to3.pgen2.token import EQEQUAL
from multiprocessing import current_process, process
from multiprocessing.sharedctypes import Value
from operator import indexOf
import ipaddress
from tkinter import E, W
import winreg as reg
import lib.Export
import numpy as np
from os import scandir
from signal import Signals
from unittest.util import sorted_list_difference
from PyQt5.QtGui import *
import threading
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from datetime import date, datetime
import re
import nest_asyncio
from PyQt5.uic import loadUi
from PyQt5.QtWebSockets import *
from datetime import datetime
from matplotlib.figure import Figure
import asyncio
import glob
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import threading
from asyncqt import QEventLoop
from scapy.all import *
import matplotlib.pyplot as plt
from scapy import *
import matplotlib
import pyshark
import multiprocessing
from lib import *
from lib.Alert import Alert
from lib.Detection import Detection
from lib.Learning import Learning
from lib.Logging import Logging
from lib.Rule import Rule
from lib.Export import Export
from lib.DataPreprocess import Datapreprocess
from ui.design import Ui_MainWindow
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

alertThreshold=0
currentAlgo="knn"
pred = Learning()
pred.getSpecificDF()
pred.splitTrainTestData()
# asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
class IDS_Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.trigger=True
        #Initialize the rule 
        self.setWindowTitle("SENTINEL")
        self.rule=rule_thread()
        self.ruleThread=QThread()
        self.ruleThread.started.connect(self.rule.run)
        self.rule.updateRuleEvent.connect(self.updateRuleEvent)
        self.rule.currentRuleSig.connect(self.updateLivePacket)
        self.rule.moveToThread(self.ruleThread)
        #Initialize the prediction
        self.predict=predict_thread()
        self.predictThread=QThread()
        self.predictThread.started.connect(self.predict.run)
        self.predict.predictionSig.connect(self.updateGraph)
        self.predict.updateEventSig.connect(self.updateEvent)
        self.predict.moveToThread(self.predictThread)
        #Variable init
        self.slicer_value=-100
        self.Detection_range=0
        self.algoIndex=0
        self.boot=1
        self.initConfiguration()

        # get data for listview
        self.collectedRule=[]
        self.emailList=[]
        self.eventList=[]
        self.thread={}
        self.loop=None

        #variable for graph
        self.benign =0
        self.malicious=0
        self.bruteForce=0
        self.ddos=0
        self.webBase=0
        self.others=0
        self.initGraphData()

        # Menu listView (Changing page)
        self.ui.stackedWidget.setCurrentIndex(0)
        self.ui.menu_listView.item(0).setSelected(True)
        self.ui.menu_listView.clicked.connect(self.change_page)

        #Dashboard attack type
        self.attackLayout=QVBoxLayout(self.ui.attack_frame)
        self.scene=QGraphicsScene()
        self.attackType_graph=QGraphicsView(self.scene)
        #init
        self.attackTypeFigure,self.attackAX=plt.subplots(figsize=(7.8,4.5))
        self.attackAX.set_title("Packets analysed from machine learning")
        self.attackAX.set_ylabel("Detected packet")
        self.attackAX.set_xlabel("Attack Type")
        attacktype=["Benign","BruteForce","DDOS","Web based","Others"]
        attackData=[self.benign,self.bruteForce,self.ddos,self.webBase,self.others]
        self.color=["Green","orange","red","blue","black"]
        self.attackAX.bar(attacktype,attackData,color=self.color)
        self.attackCanvas=FigureCanvas(self.attackTypeFigure)
        self.proxy_widget = QGraphicsProxyWidget()
        self.proxy_widget.setWidget(self.attackCanvas)
        self.scene.addItem(self.proxy_widget)
        self.attackLayout.addWidget(self.attackType_graph)
        self.attackType_graph.show()

        #Dashboard packet type
        self.packetLayout=QVBoxLayout(self.ui.packetType_frame)
        self.packetScene=QGraphicsScene()
        self.packetType_graph=QGraphicsView(self.packetScene)
        #init
        self.packetTypeFigure,self.packetAX=plt.subplots(figsize=(7.8,3.85))
        self.packetAX.set_title("Packets analysed from machine learning")
        packettype=["Benign","Malicious"]
        if self.benign==0:
            self.benign=1
        packetData=[self.benign,self.malicious]
        self.packetAX.pie(packetData,labels=packettype,autopct='%1.0f%%')
        self.packetCanvas=FigureCanvas(self.packetTypeFigure)
        self.packetwidget = QGraphicsProxyWidget()
        self.packetwidget.setWidget(self.packetCanvas)
        self.packetScene.addItem(self.packetwidget)
        self.packetLayout.addWidget(self.packetType_graph)
        self.packetType_graph.show()
        
        #Event page
        self.eventModel=QStandardItemModel()
        self.eventModel.setHorizontalHeaderLabels(["TimeStamp","Event","Type","Detail","Src Source","Src Port","Dst Source","Dst Port"])
        eventHeader = self.ui.eventTableView.horizontalHeader()
        eventHeader.setSectionResizeMode(QHeaderView.Stretch)     
        self.eventfilterModel=CustomProxyModel()
        self.eventfilterModel.setSourceModel(self.eventModel)
        self.ui.eventTableView.setModel(self.eventfilterModel)
        self.eventfilterModel.dataChanged.connect(lambda:self.updateDataOnTxt(self.ui.eventTableView,filepath="event.txt"))
        self.ui.eventSearch1_editText.textChanged.connect(lambda text:self.eventfilterModel.setFilter(text,self.ui.eventSearch1_comboBox.currentIndex()))
        self.ui.eventSearch2_editText.textChanged.connect(lambda text:self.eventfilterModel.setFilter(text,self.ui.eventSeach2_comboBox.currentIndex()))


        #Rule page
        self.model=QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Type","Source IP","Port","Dst IP","Port"])
        header = self.ui.rules_tableView.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)     
        # self.filterModel=QSortFilterProxyModel()
        # self.filterModel.setSourceModel(self.model)
        # self.filterModel.setFilterKeyColumn(-1)
        self.filterModel=CustomProxyModel()
        self.filterModel.setSourceModel(self.model)
        self.ui.rules_tableView.setModel(self.filterModel)
        self.ui.addRules_button.clicked.connect(self.addRule)
        self.filterModel.dataChanged.connect(lambda:self.updateDataOnTxt(self.ui.rules_tableView,"userDefineRule.txt"))
        self.ui.searchRulesIP_editText.textChanged.connect(lambda text:self.filterModel.setFilter(text,self.ui.ruleSearch1_comboBox.currentIndex()))
        self.ui.searchRulesPort_editText.textChanged.connect(lambda text:self.filterModel.setFilter(text,self.ui.ruleSearch2_comboBox.currentIndex()))

        #Setting page
            #slicer
        self.ui.detectionLevel_slicer.setMinimum(-100)
        self.ui.detectionLevel_slicer.setMaximum(-30)
        self.ui.detectionLevel_slicer.setValue(self.slicer_value)
        self.ui.detectionLevel_slicer.sliderReleased.connect(self.slicerChange)

            #detect range
        if self.Detection_range == 0:
            self.ui.detection_rangeOnly_radioButton.setChecked(True)
        else:
            self.ui.detection_entireNetwork_radioButton.setChecked(True)
    
            #setup email recepient
            #create email table
        self.emailModel=QStandardItemModel()
        self.emailModel.setHorizontalHeaderLabels(["Email List"])
        header = self.ui.email_tableView.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        self.ui.email_tableView.setModel(self.emailModel)
        self.ui.addEmail_button.clicked.connect(lambda:Thread(target=self.addEmail).start())
        self.emailModel.dataChanged.connect(lambda:self.updateDataOnTxt(self.ui.email_tableView,"email.txt"))

            #algorithm combo box
        algorithm=["randomForest","adaboost","decisionTree","knn","naiveBayes"]
        self.ui.algorithms_comboBox.addItems(algorithm)
        self.ui.algorithms_comboBox.setCurrentIndex(self.algoIndex)
        self.ui.algorithms_comboBox.currentIndexChanged.connect(self.updateAlgoComboBox)
        global currentAlgo
        currentAlgo=self.ui.algorithms_comboBox.currentText()

            #retrain data
        self.ui.retrainData_button.clicked.connect(lambda:Thread(target=self.retrainAllData).start())

        #Export page
        self.ui.fileLocation_address_editText.setDisabled(True)
        exportFormat=["XML","JSON","Parquet","HTML","EXCEL","pickle"]
        self.ui.exportFormat_comboBox.addItems(exportFormat)
        self.ui.openFile_button.clicked.connect(self.getExportPathDirectory)
        self.ui.fileToExportButton.clicked.connect(self.getTargetDirectory)
        self.ui.export_button.clicked.connect(lambda:Thread(target=self.export).start())
        
        #Startup
        self.ui.starupBoot_comboBox.setCurrentIndex(self.boot)
        self.ui.starupBoot_comboBox.currentIndexChanged.connect(self.updateBootComboBox)
        #Get data and search in model
        self.getData()

###INIT FUNCTION
    def initConfiguration(self):
        if not os.path.exists("miscellaneous\\configuration.txt"):
            initString="slicer_value = -100\nDetection_range=0\nalgo=3\nboot=1"
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
                        global alertThreshold
                        alertThreshold=abs(int(splited[1]))
                    elif "Detection_range" in splited[0]:
                        self.Detection_range=int(splited[1])
                    elif "algo" in splited[0]:
                        self.algoIndex=int(splited[1])
                    elif "boot" in splited[0]:
                        self.boot=int(splited[1])
                file.close()

    def initGraphData(self):
        with open("miscellaneous\\attackGraph.txt", "r") as file:
            var = file.readlines()
            for item in var:
                splited=item.replace("\n","").strip().split("=")
                if "Benign" in splited[0]:
                    self.benign=int(splited[1])
                elif "Malicious" in splited[0]:
                    self.malicious=int(splited[1])
                elif "BruteForce" in splited[0]:
                    self.bruteForce=int(splited[1])
                elif "DDOS" in splited[0]:
                    self.ddos=int(splited[1])
                elif "Webbase" in splited[0]:
                    self.webBase=int(splited[1])
                elif "Others" in splited[0]:
                    self.others=int(splited[1])
            file.close()
    
    def getData(self):
        try:
            with open("miscellaneous\\userDefineRule.txt","r") as file:
                data = file.readlines()
                if data is not None or data !="":
                    for item in data:
                        self.collectedRule.append(item.replace("\n",""))
                    for index,item in enumerate(self.collectedRule):
                        split=str(item).split(",")
                        for i in range(0,5):
                            self.model.setItem(index,i,QStandardItem(split[i]))
                file.close()
            with open("miscellaneous\\email.txt","r") as file:
                emailItem=file.readlines()
                if emailItem is not None or emailItem !="":
                    for item in emailItem:
                        self.emailList.append(item.replace("\n",""))
                    for i in self.emailList:
                        self.emailModel.appendRow(QStandardItem(i))
                file.close
            with open("miscellaneous\\event.txt","r") as file:
                eventItem=file.readlines()
                if eventItem is not None or eventItem !="":
                    for item in eventItem:
                        self.eventList.append(item.replace("\n",""))
                    for index,item in enumerate(self.eventList):
                        split=str(item).split(",")
                        for i in range(0,8):
                            self.eventModel.setItem(index,i,QStandardItem(split[i]))
                file.close
        except FileNotFoundError as e:
            Logging.logException(str(e))

###PAGE CHANGE
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
                Alert("Starting","Initialising the sniffer").generateDesktopNotification()
                self.predictThread.start()
                self.ruleThread.start()
                self.trigger = False
            else:
                self.trigger = True
###DASHBOARD FUNCTIONS
    def updateGraph(self,item):
            type_bruteforce=["FTP-BruteForce","SSH-Bruteforce"]
            type_dos=[
            "DoS attacks-GoldenEye",
            "DoS attacks-Slowloris",
            "DoS attacks-SlowHTTPTest",
            "DoS attacks-Hulk"]
            type_ddos=["DDoS attacks-LOIC-HTTP","DDOS attack-LOIC-UDP","DDOS attack-HOIC"]
            type_webBased=["Brute Force -Web","Brute Force -XSS","SQL Injection"]
            type_others=["Infilteration","Bot"]
            for label, predict, detail in item:
                if float(predict) >= alertThreshold:
                    if label in type_bruteforce:
                        self.bruteForce +=1
                        self.malicious +=1
                    elif label in type_ddos or label in type_dos:
                        self.ddos+=1
                        self.malicious+=1
                    elif label in type_webBased:
                        self.webBase+=1
                        self.malicious+=1
                    elif label in type_others:
                        self.others+=1
                        self.malicious+=1
                if label == "Benign":
                    self.benign+=1
            #attacktype]
            data={"Benign":self.benign,"BruteForce":self.bruteForce,"DDOS":self.ddos,"Web based":self.webBase,"Others":self.others}
            attackLabel = list(data.keys())
            count = list(data.values())
            self.attackAX.clear()
            self.attackAX.set_xlabel("Attack type")
            self.attackAX.set_ylabel("Detected packet")
            self.attackAX.set_title("Packet analysed from machine learning")
            self.attackAX.bar(attackLabel,count,color=self.color)
            self.attackCanvas.draw()
            self.attackCanvas.flush_events()
            
            #packetType
            packetData={"Benign":self.benign,"Malicious":self.malicious}
            packetLabel=list(packetData.keys())
            total=list(packetData.values())
            self.packetAX.clear()
            self.packetAX.set_title("Packet analysed from machine learning")
            self.packetAX.pie(total,labels=packetLabel,autopct='%1.0f%%')
            self.packetCanvas.draw()
            self.packetCanvas.flush_events()

            with open("miscellaneous\\attackGraph.txt","w") as file:
                item="Benign = {} \nMalicious = {} \nBruteForce = {} \nDDOS = {} \nWebbase = {} \nOthers = {}".format(self.benign,self.malicious,self.bruteForce,self.ddos,self.webBase,self.others)
                file.write(item)
                file.close()
        
    def updateEvent(self,data):
        try:
            type_bruteforce=["FTP-BruteForce","SSH-Bruteforce"]
            type_dos=[
            "DoS attacks-GoldenEye",
            "DoS attacks-Slowloris",
            "DoS attacks-SlowHTTPTest",
            "DoS attacks-Hulk"]
            type_ddos=["DDoS attacks-LOIC-HTTP","DDOS attack-LOIC-UDP","DDOS attack-HOIC"]
            type_webBased=["Brute Force -Web","Brute Force -XSS","SQL Injection"]
            type_others=["Infilteration","Bot"]
            for label, predict, detail in data:
                currentIP_Detail=detail.split(",")
                if float(predict) >= alertThreshold and ("0.0.0.0" not in currentIP_Detail[0] or "255.255.255.255" not in currentIP_Detail[2]) :
                    if label in type_bruteforce:
                        self.ui.currentEvent_textBrower.append(f"BruteForce attempted: {label}  {predict}%")
                    elif label in type_ddos or label in type_dos:
                        self.ui.currentEvent_textBrower.append(f"DDOS attempted: {label}  {predict}%")
                    elif label in type_webBased:
                        self.ui.currentEvent_textBrower.append(f"WebBased attempted: {label}  {predict}%")
                    elif label in type_others:
                        self.ui.currentEvent_textBrower.append(f"Others attempted: {label}  {predict}%")
                    if label not in "Benign":
                        ipdate=currentIP_Detail[4][:11]
                        ipTime=currentIP_Detail[4][11:]
                        eventStr=f"{ipdate} {ipTime},{label},Prediction,Probability: {predict} %,{currentIP_Detail[0]},{currentIP_Detail[1]},{currentIP_Detail[2]},{currentIP_Detail[3]}"
                        self.eventList.append(eventStr)
                        self.eventModel.clear()
                        self.eventModel.setHorizontalHeaderLabels(["TimeStamp","Event","Type","Detail","Src Source","Src Port","Dst Source","Dst Port"])
                        for index,item in enumerate(self.eventList):
                            split=str(item).split(",")
                            for i in range(0,8):
                                self.eventModel.setItem(index,i,QStandardItem(split[i]))
                        if not os.path.exists("miscellaneous\\event.txt"):
                            with open("miscellaneous\\event.txt","w") as file:
                                file.write(eventStr)
                                file.close()
        except Exception as e:
            Logging.logException(str(e))
###EVENT FUNCTIONS
    def updateRuleEvent(self,data):
        #data[0]=srcip
        #data[1]=srcport
        #data[2]=dstip
        #data[3]=dstport
        #data[4]=classtype
        #data[5]=message
        eventStr=f"{str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))},{data[4]},Rules,{data[5]},{data[0]},{data[1]},{data[2]},{data[3]}"
        self.eventList.append(eventStr)
        self.eventModel.clear()
        self.eventModel.setHorizontalHeaderLabels(["TimeStamp","Event","Type","Detail","Src Source","Src Port","Dst Source","Dst Port"])
        self.ui.currentEvent_textBrower.append(str(data[4]))
        for index,item in enumerate(self.eventList):
            split=str(item).split(",")
            for i in range(0,8):
                self.eventModel.setItem(index,i,QStandardItem(split[i]))
        if not os.path.exists("miscellaneous\\event.txt"):
            with open("miscellaneous\\event.txt","w") as file:
                file.write(eventStr)
                file.close()

###RULE FUNCTIONS
    def addRule(self):
        def checkValidIP(ipString):
            try:
                ipaddress.ip_network(ipString)
            except:
                return False
            return True

        def checkValidPort(portString):
            try:
                if (int(portString) >= 0 and int(portString) <=65535):
                    return True
                else:
                    return False
            except ValueError as e :
                if str(portString).lower().strip()=="any":
                    return True
                else:
                    return False
        ruleType=str(self.ui.packetType_comboBox.currentText())
        srcIP=self.ui.add_srcIP_editText.text()
        srcPort=self.ui.add_srcPort_editText.text()
        dstIP=self.ui.add_dstIP_editText.text()
        dstPort=self.ui.add_dstPort_editText.text()
        
        if checkValidIP(srcIP) and checkValidIP(dstIP):
            if checkValidPort(srcPort) and checkValidPort(dstPort):
                rule = "{},{},{},{},{}".format(ruleType,srcIP,srcPort,dstIP,dstPort)
                self.collectedRule.append(rule)
                self.model.clear()
                self.model.setHorizontalHeaderLabels(["Type","Source IP","Port","Dst IP","Port"])
                for index,item in enumerate(self.collectedRule):
                    split=str(item).split(",")
                    for i in range(0,5):
                        self.model.setItem(index,i,QStandardItem(split[i]))
                if not os.path.exists("miscellaneous\\userDefineRule.txt"):
                    with open("miscellaneous\\userDefineRule.txt","w") as file:
                        file.write(rule)
                        file.close()
                self.ui.add_srcIP_editText.setText("")
                self.ui.add_srcPort_editText.setText("")
                self.ui.add_dstIP_editText.setText("")
                self.ui.add_dstPort_editText.setText("")
            else:
                Alert("Unknow network port ","Please make sure the port is within range 0-65535 or use any to get all port").generateDesktopNotification()
        else:
            Alert("Unknow IP address","Please make sure the ip format is correct").generateDesktopNotification()
    
###SETTING FUNCTIONS
    def slicerChange(self):
        value = self.ui.detectionLevel_slicer.value()
        self.changeVariableOnTxt("slicer_value = {}".format(self.slicer_value),"slicer_value = {}".format(value))
        self.slicer_value=value
        global alertThreshold
        alertThreshold=abs(self.slicer_value)

    def updateAlgoComboBox(self):
        index=self.ui.algorithms_comboBox.currentIndex()
        self.changeVariableOnTxt("algo={}".format(self.algoIndex),"algo={}".format(index))
        global currentAlgo
        currentAlgo=self.ui.algorithms_comboBox.currentText()

    def updateBootComboBox(self):
        index=self.ui.starupBoot_comboBox.currentIndex()
        self.changeVariableOnTxt("boot={}".format(self.boot),"boot={}".format(index))
        self.starupOnBoot(int(index))

    def changeVariableOnTxt(self,ori,replace):
        with open("miscellaneous\\configuration.txt", "r") as file:
            data=file.read()
            data=data.replace(ori,replace)
            file.close()
        with open("miscellaneous\\configuration.txt", "w") as file:
            file.write(data)
            file.close()

    def addEmail(self):
        email= self.ui.email_editText.text()
        emailPattern = "[\w.]+\@[\w.]+"
        if re.search(emailPattern, email) and email!= "":
            self.emailList.append(email)
            self.emailModel.clear()
            self.emailModel.setHorizontalHeaderLabels(["Email List"])
            for i in self.emailList:
                self.emailModel.appendRow(QStandardItem(i))
            if not os.path.exists("miscellaneous\\email.txt"):
                with open("miscellaneous\\email.txt","w") as file:
                    file.write(email)
                    file.close()
            else:
                with open("miscellaneous\\email.txt","a") as file:
                    file.write("\n{}".format(email))
                    file.close()
            Alert("Successfully saved the email","").generateDesktopNotification()
            Alert("Welcome to sentinel","You has been added to received notification email from sentinel, any threat will be notify to you via email and notification").sendEmail(personalEmail=email)
            self.ui.email_editText.setText("")
        else:
            Alert("Invalid email format","Please enter valid email").generateDesktopNotification()
            self.ui.email_editText.setText("")
    
    def retrainAllData(self):
        # if os.path.exists("training\\cleanedData"):
        #     print("Deleting existing csv file in cleanedData")
        #     filelist = glob("training\\cleanedData" + "\\*.csv")
        #     for file in filelist:
        #         os.remove(file)
        # print("Start sampling data")
        # for dirname, _, filenames in os.walk("training\\dataset"):
        #     for filename in filenames:
        #         pds=[]
        #         if filename.endswith('.csv'):
        #             pds = os.path.join(dirname, filename)
        #             Datapreprocess(pds).sampleCleanEachLabelEqualy(percentage=0.3)
        Alert("Regenerating the prediction model","Please allow program execution until the complete notification show").generateDesktopNotification()
        retrain=Learning()
        retrain.getSpecificDF()
        retrain.splitTrainTestData()
        retrain.overwriteAllModel()
        Alert("Successful generate the model","").generateDesktopNotification()

    def starupOnBoot(self,index):
        try:
            pth = os.path.dirname(os.path.realpath(__file__))
            intendedScript="SENTINEL.bat"
            address=os.path.join(pth,intendedScript)
            key = reg.HKEY_CURRENT_USER
            key_value = "Software\Microsoft\Windows\CurrentVersion\Run"
            openkey = reg.OpenKey(key,key_value,0,reg.KEY_ALL_ACCESS)
            if index ==0:
                reg.SetValueEx(openkey,"SENTINEL",0,reg.REG_SZ,address)
            else:
                reg.DeleteValue(openkey,"SENTINEL")
            reg.CloseKey(openkey)
        except:
            pass

###EXPORT FUNCTIONS
    def getTargetDirectory(self):
        path=str(QFileDialog.getOpenFileNames())
        self.ui.targetFile_editText.setText(path)
        
    def getExportPathDirectory(self):
        path=str(QFileDialog.getExistingDirectory())
        self.ui.fileLocation_address_editText.setText(path)

    def export(self):
        target=self.ui.targetFile_editText.text()
        split=target.replace("([","").replace("]","").replace("'","").split(",")
        path=self.ui.fileLocation_address_editText.text()
        fileformat=self.ui.exportFormat_comboBox.currentText()
        self.ui.exportProgress.setValue(0)
        if target!=None or target!="":
            for i in range(0,len(split)-1):
                filetarget=str(split[i]).replace("/","\\").strip()
                if path != "":
                    fileLoc=path.replace("/","\\")
                else:
                    fileLoc="exported"
                if fileformat=="XML":
                    Export(filetarget,fileLoc).to_XML()
                elif fileformat=="JSON":
                    Export(filetarget,fileLoc).to_JSON()
                elif fileformat=="Parquet":
                    Export(filetarget,fileLoc).to_parquet()
                elif fileformat=="HTML":
                    Export(filetarget,fileLoc).to_HTML()
                elif fileformat=="EXCEL":
                    Export(filetarget,fileLoc).to_excel()
                elif fileformat=="pickle":
                    Export(filetarget,fileLoc).to_pickle()
                self.ui.exportProgress.setValue(round((i+1)/(len(split)-1)*100))
            Alert("Export completed","{} has been generated on {} folder".format(fileformat,fileLoc)).generateDesktopNotification()
     
### RECEIVED FROM PYQT FUNCTIONS
    def updateLivePacket(self,ip):
        self.ui.livePacket_textBrowser.append(ip)

    def updateEventTextBrower(self,event):
        self.ui.currentEvent_textBrower.append(event)

### Miscellaneous
    def updateDataOnTxt(self,tableview,filepath=""):
        model = tableview.model()
        concatData=""
        data = []
        for row in range(model.rowCount()):
            data.append([])
            for column in range(model.columnCount()):
                index = model.index(row, column)
                data[row].append(str(model.data(index)))
        for i in data:
            concatData+=",".join(i)+"\n"
        try:
            if len(data)>0:
                with open(f"miscellaneous\\{filepath}","w") as file:
                    file.write(concatData)
                    file.close()
        except FileNotFoundError:
           Logging.logException(f"{filepath} not found")
           
### Custom filtering
class CustomProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._filters = dict()

    @property
    def filters(self):
        return self._filters

    def setFilter(self, expresion, column):
        if expresion:
            self.filters[column] = expresion
        elif column in self.filters:
            del self.filters[column]
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        for column, expresion in self.filters.items():
            text = self.sourceModel().index(source_row, column, source_parent).data()
            regex = QRegExp(
                expresion, Qt.CaseInsensitive, QRegExp.RegExp
            )
            if regex.indexIn(text) == -1:
                return False
        return True

class RuleCustomProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._filters = dict()
        self.text=""

    @property
    def filters(self):
        return self._filters

    def setFilter(self, expresion):
        # if expresion:
        #     self.filters[column] = expresion
        # elif column in self.filters:
        #     del self.filters[column]
        self.text=expresion
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        ipSrcIndex=self.sourceModel().index(source_row, 1, source_parent)
        ipdstIndex=self.sourceModel().index(source_row, 3, source_parent)
        ip=self.sourceModel().data(ipSrcIndex)
        dst=self.sourceModel().data(ipdstIndex)
        regex = QRegExp(
            self.text, Qt.CaseInsensitive, QRegExp.RegExp
        )

        if not regex.indexIn(ip) and not regex.indexIn(dst):
            return False
        return True


###THREADING FOR SNIFF AND PREDICT  FUNCTION
class rule_thread(QObject):
    currentRuleSig=pyqtSignal(str)
    updateRuleEvent=pyqtSignal(list)
    def __init__(self):
        super().__init__()

    @pyqtSlot()
    def run(self):
        try:
            self.is_running = True
            self.loop= asyncio.new_event_loop()
            # self.loop.run_forever()
            asyncio.set_event_loop(loop=self.loop)
            nest_asyncio.apply(loop=self.loop)
            self.loop.create_task(self.sniff())
            # asyncio.run_coroutine_threadsafe(self.testSniffing(),self.loop)
        except Exception as e:
            Logging.logException(str(e))

    def sniff(self):
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
                    Rule.checkUserBanIP("TCP",src_ip,src_port,dst_ip,dst_port)
                    self.currentRuleSig.emit("[TCP] {}       \t{}\t-> {}\t{}".format(src_ip, src_port, dst_ip, dst_port))
                    if "segment_data" in dir(packet["TCP"]):
                        payload = packet["TCP"].segment_data
                        payload = str(payload).replace(":", " ")
                        ruleTrigger=Rule("tcp", src_ip, src_port, dst_ip, dst_port).checkRules(
                            payload
                        )
                        if ruleTrigger is not None:
                            self.updateRuleEvent.emit(ruleTrigger)
                if packet.transport_layer == "UDP":
                    udp_srcport=packet["UDP"].srcport
                    udp_dstport=packet["UDP"].dstport
                    self.currentRuleSig.emit("[UDP] {}       \t{}\t-> {}\t{}".format(src_ip, udp_srcport, dst_ip, udp_dstport))
                    if "segment_data" in dir(packet["UDP"]):
                        payload = packet["UDP"].segment_data
                        payload = str(payload).replace(":", " ")
                        Rule.checkUserBanIP("UDP",src_ip,src_port,dst_ip,dst_port)
                        ruleTrigger=Rule("udp", src_ip, udp_srcport, dst_ip, udp_dstport).checkRules(
                            payload
                        )
                        if ruleTrigger is not None:
                            self.updateRuleEvent.emit(ruleTrigger)

class predict_thread(QObject):
    predictionSig=pyqtSignal(zip)
    updateEventSig=pyqtSignal(zip)
    is_running=False
    def __init__(self):
        super().__init__()

    @pyqtSlot()
    def run(self):
        self.is_running=True
        while True:
            try:
                predictionItem,currentPacketDetail=Detection.prediction(algo=currentAlgo,classes=pred.x_train,threshold=alertThreshold)
                packetDetail = []
                if currentPacketDetail is not None and predictionItem is not None:
                    for index,item in enumerate(currentPacketDetail):
                        packetDetail.append(str(currentPacketDetail[index]).replace("'","").replace("[","").replace("]",""))
                    zipItem=zip(predictionItem[0],predictionItem[1],packetDetail)
                    self.predictionSig.emit(zipItem)
                    zipItem2=zip(predictionItem[0],predictionItem[1],packetDetail)
                    self.updateEventSig.emit(zipItem2)
            except Exception as e:
                pass
        
if __name__ == "__main__":
    app = QApplication([])
    window = IDS_Window()
    with open("ui\\SyNet.qss", "r") as file:
        window.setStyleSheet(file.read())
    window.show()
    app.exec()
