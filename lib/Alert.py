from multiprocessing import context
import ssl
import smtplib
import os
import platform
from lib.Logging import *
# from Logging import Logging
from email.message import EmailMessage
from dotenv import load_dotenv
_=load_dotenv("var.env")
if platform.system() == "Windows":
    import win10toast 
elif platform.system() == "Linux":
    import subprocess
class Alert:
    def __init__(self,msg_title,msg_content):
        self.msg_title=msg_title
        self.msg_content=msg_content
        self.imgIcon="resources\\logo.ico"
        self.emailList=self.getEmailList()

    def getEmailList(self):
        emailArray=[]
        with open("miscellaneous\\email.txt","r") as file:
            line = file.readlines()
            for item in line:
                emailArray.append(item.replace("\n",""))
            file.close()
            return emailArray

    def generateDesktopNotification(self,thread=False):
        win10toast.ToastNotifier().show_toast(self.msg_title,self.msg_content,self.imgIcon,5,threaded=thread)

    def sendEmail(self,personalEmail=None):
        try:
            address = os.environ.get("EMAIL_ADDRESS")
            passw = os.environ.get("EMAIL_PASSWORD")
            msg = EmailMessage()
            msg['Subject'] = self.msg_title
            msg['From'] = address
            if not personalEmail == None:
                 mail=[personalEmail]
                 msg['To'] = mail
            else:
                msg['To'] = self.emailList
            msg.set_content(self.msg_content)

            with smtplib.SMTP_SSL('smtp.gmail.com', port=465) as smtp:
                smtp.login(address, passw)
                smtp.send_message(msg)
                smtp.quit()
            Logging.logInfo("Successful send the email to {}".format(str(self.emailList)))
        except Exception as e:
            Logging.logException(str(e))
        
