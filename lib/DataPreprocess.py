
from codecs import ignore_errors, latin_1_decode
from enum import unique
from re import S
from statistics import mean
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import f_regression
from sklearn.feature_selection import chi2
from sklearn.feature_selection import SelectKBest
import matplotlib
import os


class Datapreprocess:
    def __init__(self, data):
        self.readData=pd.read_csv(data)
        self.encodeData = ""
        self.currentAvailableLabel = ""
        self.extractFeatureDf=""
        self.bestFeature=""

    def getLabelType(self):
        df = pd.DataFrame(self.readData)
        self.currentAvailableLabel = df["Label"].unique()

    def encodeFeature(self):
        label = LabelEncoder()
        self.encodeData = self.readData
        label.fit(self.encodeData.Label.drop_duplicates())
        self.encodeData.Label = label.transform(self.encodeData.Label)
        return self.encodeData

    def datacleaning(self):
        pd.option_context("mode.use_inf_as_na", True)
        # Timestamp and protocol does not affect the result
        toRemove=["Flow ID","Src IP","Src Port","Dst IP"]
        if "Flow ID" in self.readData:
            self.readData.drop(toRemove,inplace=True,axis=1)
        elif "Timestamp" in self.readData:
            self.readData.drop("Timestamp", inplace=True, axis=1)
        elif "Protocol" in self.readData:
            self.readData.drop("Protocol", inplace=True, axis=1)
        self.readData.drop_duplicates(inplace=True)
        self.readData.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.readData.dropna(axis=0, inplace=True)

    def getMissingValuePercentage(self):
        pd.set_option("display.max_rows", None)
        df = pd.DataFrame(self.readData)
        print(df.isna().sum() / len(df) * 100)


    def getBestFeature(self, top=10):
        self.datacleaning()
        self.encodeFeature()
        x = self.encodeData.iloc[:, :-1]
        y = self.encodeData.iloc[:, -1]
        x[x<0]=0
        feature = SelectKBest(score_func=f_regression, k=top)
        fit = feature.fit(x, y)
        dfscores = pd.DataFrame(fit.scores_)
        dfcolumns = pd.DataFrame(x.columns)
        featureScores = pd.concat([dfcolumns, dfscores], axis=1)
        featureScores.columns = ["Feature", "Score"]
        self.extractFeatureDf=x.iloc[:,feature.get_support(indices=True)]
        # print(self.extractFeatureDf)
        # print(featureScores.nlargest(top, "Score"))
        return self.extractFeatureDf
       

    def getDtype(self):
        pd.set_option("display.max_rows", None)
        print(self.readData.dtypes)

    def getShape(self):
        df = pd.DataFrame(self.readData)
        self.getLabelType()
        for label in self.currentAvailableLabel:
            print(label)
            print(df.loc[df["Label"].isin([label])].shape)

    def sampleCleanEachLabelEqualy(self):
        self.datacleaning()
        # self.encodeFeature()
        df = pd.DataFrame(self.readData)
        self.getLabelType()
        type_bruteforce=["FTP-BruteForce","SSH-Bruteforce"]
        type_dos=["DoS attacks-GoldenEye","DoS attacks-Slowloris","DoS attacks-SlowHTTPTest","DoS attacks-Hulk"]
        type_ddos=["DDoS attacks-LOIC-HTTP","DDOS attack-LOIC-UDP","DDOS attack-HOIC"]
        type_webBased=["Brute Force -Web","Brute Force -XSS","SQL Injection"]
        type_others=["Infilteration","Bot"]
        previousSaveData=pd.DataFrame()
        if not os.path.exists("training\\cleanedData"):
            os.mkdir("training\\cleanedData")
        print("start undersampling {}".format(self.currentAvailableLabel))
        for label in self.currentAvailableLabel:
                if label in type_bruteforce:
                    benignRow=df.loc[df["Label"].isin(["Benign"])].shape[0]
                    labelRow = df.loc[df["Label"].isin([label])].shape[0]
                    newData=df.loc[df["Label"].isin(["Benign"])].sample(round(labelRow*0.2))
                    currentRow=df.loc[df["Label"].isin([label])].sample(round(labelRow*0.2))
                    print("found {} size {}".format(label,labelRow))
                    currentDf=pd.concat([newData,currentRow],axis=0).drop_duplicates()
                    currentDf.drop(currentDf.filter(regex="Unname"),axis=1, inplace=True)
                    if previousSaveData.empty and not os.path.exists("training\\cleanedData\\bruteforce.csv"):
                        pd.DataFrame(currentDf).to_csv("training\\cleanedData\\bruteforce.csv",index=False)
                        previousSaveData=currentDf
                    else:
                        previousSaveData=pd.DataFrame(pd.read_csv("training\\cleanedData\\bruteforce.csv"))
                        newDataframe=pd.concat([previousSaveData,currentDf],axis=0)
                        newDataframe.drop(newDataframe.filter(regex="Unname"),axis=1, inplace=True)
                        previousSaveData=newDataframe.drop_duplicates()
                        pd.DataFrame(newDataframe).to_csv("training\\cleanedData\\bruteforce.csv",index=False)
                    continue        
                elif label in type_dos or label in type_ddos:
                    benignRow=df.loc[df["Label"].isin(["Benign"])].shape[0]
                    labelRow = df.loc[df["Label"].isin([label])].shape[0]
                    newData=df.loc[df["Label"].isin(["Benign"])].sample(round(labelRow*0.2))
                    currentRow=df.loc[df["Label"].isin([label])].sample(round(labelRow*0.2))
                    print("found {} size {}".format(label,labelRow))
                    currentDf=pd.concat([newData,currentRow],axis=0,ignore_index=True,join='inner').drop_duplicates()
                    currentDf.drop(currentDf.filter(regex="Unname"),axis=1, inplace=True)
                    if previousSaveData.empty and not os.path.exists("training\\cleanedData\\ddos.csv"):
                        pd.DataFrame(currentDf).to_csv("training\\cleanedData\\ddos.csv",index=False)
                        previousSaveData=currentDf
                    else:
                        previousSaveData=pd.DataFrame(pd.read_csv("training\\cleanedData\\ddos.csv",on_bad_lines="skip"))
                        newDataframe=pd.concat([previousSaveData,currentDf],axis=0)
                        newDataframe.drop(newDataframe.filter(regex="Unname"),axis=1, inplace=True)
                        previousSaveData=newDataframe.drop_duplicates()
                        pd.DataFrame(newDataframe).to_csv("training\\cleanedData\\ddos.csv",index=False) 
                    continue  
                elif label in type_webBased:
                    benignRow=df.loc[df["Label"].isin(["Benign"])].shape[0]
                    labelRow = df.loc[df["Label"].isin([label])].shape[0]
                    newData=df.loc[df["Label"].isin(["Benign"])].sample(round(labelRow*0.2))
                    currentRow=df.loc[df["Label"].isin([label])].sample(round(labelRow*0.2))
                    print("found {} size {}".format(label,labelRow))
                    currentDf=pd.concat([newData,currentRow],axis=0,ignore_index=True,join='inner')
                    currentDf.drop(currentDf.filter(regex="Unname"),axis=1, inplace=True)
                    if previousSaveData.empty and not os.path.exists("training\\cleanedData\\webbase.csv"):
                        pd.DataFrame(currentDf).to_csv("training\\cleanedData\\webbase.csv",index=False)
                        previousSaveData=currentDf
                    else:
                        previousSaveData=pd.DataFrame(pd.read_csv("training\\cleanedData\\webbase.csv"))
                        newDataframe=pd.concat([previousSaveData,currentDf],axis=0).drop_duplicates()
                        previousSaveData=newDataframe
                        newDataframe.drop(newDataframe.filter(regex="Unname"),axis=1, inplace=True)
                        pd.DataFrame(newDataframe).to_csv("training\\cleanedData\\webbase.csv",index=False) 
                    continue  
                elif label in type_others:
                    benignRow=df.loc[df["Label"].isin(["Benign"])].shape[0]
                    labelRow = df.loc[df["Label"].isin([label])].shape[0]
                    newData=df.loc[df["Label"].isin(["Benign"])].sample(round(labelRow*0.2))
                    currentRow=df.loc[df["Label"].isin([label])].sample(round(labelRow*0.2))
                    currentDf=pd.concat([newData,currentRow],axis=0).drop_duplicates()
                    currentDf.drop(currentDf.filter(regex="Unname"),axis=1, inplace=True)
                    print("found {} size {}".format(label,labelRow))
                    if previousSaveData.empty and not os.path.exists("training\\cleanedData\\others.csv"):
                        pd.DataFrame(currentDf).to_csv("training\\cleanedData\\others.csv",index=False)
                        previousSaveData=currentDf
                    else:
                        previousSaveData=pd.DataFrame(pd.read_csv("training\\cleanedData\\others.csv"))
                        newDataframe=pd.concat([previousSaveData,currentDf],axis=0,ignore_index=True,join='inner')
                        previousSaveData=newDataframe.drop_duplicates()
                        newDataframe.drop(newDataframe.filter(regex="Unname"),axis=1, inplace=True)
                        pd.DataFrame(newDataframe).to_csv("training\\cleanedData\\others.csv",index=False) 
                    continue  
        print("undersampling Done {}".format(self.currentAvailableLabel))
            # except:
            #     pass


# for dirname, _, filenames in os.walk("training\\dataset"):
#     for filename in filenames:
#         pds=[]
#         if filename.endswith('.csv'):
#             pds = os.path.join(dirname, filename)
#             Datapreprocess(pds).sampleCleanEachLabelEqualy()
# Datapreprocess("training\\dataset\\02-14-2018.csv").sampleCleanEachLabelEqualy()
# print(Datapreprocess("training\\cleanedData\\combined.csv").getBestFeature(11))
