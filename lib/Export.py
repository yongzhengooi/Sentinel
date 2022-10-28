import pandas as pd
from datetime import datetime
class Export:
    def __init__(self,csvFile,path,name=None):
        self.data=pd.read_csv(csvFile)
        self.name=str(csvFile).replace(".csv","").split("\\")[-1]
        if path =="":
            self.path="exported"
        else:
            self.path=path
        self.df=pd.DataFrame(self.data)
    
    def to_XML(self):
        self.df.to_xml(path_or_buffer="{}\\{}.xml".format(self.path,self.name))

    def to_JSON(self):
        self.df.to_json(path_or_buf="{}\\{}.json".format(self.path,self.name))

    def to_HTML(self):
        self.df.to_html(buf="{}\\{}.html".format(self.path,self.name))

    def to_parquet(self):
        self.df.to_parquet(path="{}\\{}.parquet".format(self.path,self.name))

    def to_excel(self):
        self.df.to_csv(path_or_buf="{}\\{}.xlsx".format(self.path,self.name))

    def to_pickle(self):
        self.df.to_pickle(path="{}\\{}.pickle".format(self.path,self.name))
