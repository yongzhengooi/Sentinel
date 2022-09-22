from ast import main
from ctypes import windll
from distutils.command.build import build
from operator import indexOf
from tkinter import Button
from unittest.util import sorted_list_difference
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.uic import loadUi
from PyQt5.QtWebSockets import *
import matplotlib
import re
from ui.design import Ui_MainWindow

# import tensorflow


class IDS_Window(QMainWindow):
    def __init__(self):
        super().__init__()
       # loadUi("design.ui",self)
        self.ui=Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("Network Intrusion Detection System")
        
        #Menu listView (Changing page)
        self.ui.stackedWidget.setCurrentIndex(0)
        self.ui.menu_listView.item(0).setSelected(True)
        self.ui.menu_listView.clicked.connect(self.change_page)

    def change_page(self):
        selectedPage=self.ui.menu_listView.currentItem().text()

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



# Menu layout
# class Menu_layout(QWidget):
#     def __init__(self, parent):
#         super(Menu_layout, self).__init__(parent)
#         self.menu_layout = QVBoxLayout(self)
#         self.menu_layout.layout
#         # Dashboard
#         self.dashboard_btn = QPushButton("Dashboard")
#         self.dashboard_btn.clicked.connect(self.printA)

#         # Event
#         self.event_btn = QPushButton("Event")
#         self.event_btn.clicked.connect(self.printA)

#         # Rules
#         self.rules_btn = QPushButton("Rules")
#         self.rules_btn.clicked.connect(self.printA)

#         # Setting
#         self.setting_btn = QPushButton("Setting")
#         self.setting_btn.clicked.connect(self.printA)

#         # Switch
#         self.switch_btn = QPushButton("Switch")
#         self.switch_btn.clicked.connect(self.printA)

#         # add into layout
#         self.menu_layout.addWidget(self.dashboard_btn)
#         self.menu_layout.addWidget(self.event_btn)
#         self.menu_layout.addWidget(self.rules_btn)
#         self.menu_layout.addWidget(self.setting_btn)
#         self.menu_layout.addWidget(self.switch_btn)
#         self.setLayout(self.menu_layout)

#     def printA(self):
#         pass
if __name__ == "__main__":
    app = QApplication([])
    window = IDS_Window()
    with open("ui\\SyNet.qss","r") as file:
        window.setStyleSheet(file.read())
    window.show()
    app.exec()
