from ctypes import windll
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import matplotlib
import tensorflow

if __name__=="__main__":
    app=QApplication([])
    window=QWidget()
    window.show()
    app.exec()