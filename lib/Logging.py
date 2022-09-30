import datetime
import os.path
class Logging:
    def logException(exception):
        currentDateTime=datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        try:
            if os.path.exists("log\\exception.txt"):
                with open("log\\exception.txt", "a") as file:
                    file.write("[{}] {}\n".format(currentDateTime,exception))
            else:
                with open("log\\exception.txt", "w"):
                    file.write("[{}] {}\n".format(currentDateTime,exception))
        except FileExistsError:
            pass
        finally:
            file.close()

    def logInfo(info):
        currentDateTime=datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        try:
            if os.path.exists("log\\info.txt"):
                with open("log\\info.txt", "a") as file:
                    file.write("[{}] {}\n".format(currentDateTime,info))
            else:
                with open("log\\info.txt", "w"):
                    file.write("[{}] {}\n".format(currentDateTime,info))
        except FileExistsError:
            pass
        finally:
            file.close()    

    def loggingPacket():
        pass