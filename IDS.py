from ast import main
from ctypes import windll
from distutils.command.build import build
from operator import indexOf
from pickle import FALSE, TRUE
from threading import Thread
from unittest.util import sorted_list_difference
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.uic import loadUi
from PyQt5.QtWebSockets import *
import matplotlib
import lib
import multiprocessing
from lib import Detection
from ui.design import Ui_MainWindow

# import tensorflow


class IDS_Window(QMainWindow):
    def __init__(self):
        super().__init__()
        # loadUi("design.ui",self)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("Sentinel")
        self.trigger=True
        #Startup the sniffer
        # Menu listView (Changing page)
        self.ui.stackedWidget.setCurrentIndex(0)
        self.ui.menu_listView.item(0).setSelected(True)
        self.ui.menu_listView.clicked.connect(self.change_page)

        #Display on dashborad
        self.ui.livePacket_textBrowser

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
                print("Sniffer starting")
                Detection.Detection.startOrStopSniffer(True)
                self.runSniffer()
                self.trigger = False
            else:
                print("stop")
                Detection.Detection.startOrStopSniffer(False)
                self.runSniffer()
                self.trigger = True
    def runSniffer(self):
        snifferThread = Thread(target=Detection.Detection.getPacket) 
        if self.trigger:
            snifferThread.start()
        else:
            snifferThread.terminate()

if __name__ == "__main__":
    app = QApplication([])
    window = IDS_Window()
    with open("ui\\SyNet.qss", "r") as file:
        window.setStyleSheet(file.read())
    window.show()
    app.exec()
