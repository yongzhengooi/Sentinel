from pyexpat import model
from statistics import LinearRegression, mean
import numpy as np
import glob
from sklearn.compose import ColumnTransformer
import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
import sklearn.metrics as metrics
from sklearn.ensemble import AdaBoostClassifier
from sklearn.model_selection import cross_validate
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
import joblib
from sklearn.preprocessing import LabelEncoder
import hummingbird.ml.supported
from hummingbird.ml import convert
from lib.DataPreprocess import Datapreprocess
# from DataPreprocess import Datapreprocess
from sklearn.linear_model import LogisticRegression
import torch as torch


class Learning:
    def __init__(self):
        self.data = self.combineAllCsv()
        self.x_train = []
        self.x_test = []
        self.y_train = []
        self.y_test = []

    def combineAllCsv(self):
        if not os.path.exists("training\\cleanedData\\combined.csv"):
            data = pd.concat(
                map(pd.read_csv, glob.glob("training\\cleanedData" + "\\*.csv")), axis=0
            )
            data.to_csv("training\\cleanedData\\combined.csv", index=False)
            return data
        else:
            data = pd.read_csv("training\\cleanedData\\combined.csv")
            return data

    def getSpecificDF(self):
        self.data.drop_duplicates(inplace=True)
        self.data.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.data.dropna(axis=0, inplace=True)
        if "Timestamp" in self.data:
            self.data.drop("Timestamp", inplace=True, axis=1)
        self.data = pd.concat(
            [
                Datapreprocess("training\\cleanedData\\combined.csv").getBestFeature(
                    11
                ),
                self.data.iloc[:, -1],
            ],
            axis=1,
        )

    def splitTrainTestData(self,state=153):
        self.data.dropna(axis=0,inplace=True)
        feature = self.data.iloc[:, :-1]
        label = self.data.iloc[:, -1]
        le = LabelEncoder()
        encoded = le.fit(
            [
                "Benign",
                "FTP-BruteForce",
                "SSH-Bruteforce",
                "DoS attacks-GoldenEye",
                "DoS attacks-Slowloris",
                "DoS attacks-SlowHTTPTest",
                "DoS attacks-Hulk",
                "DDoS attacks-LOIC-HTTP",
                "DDOS attack-LOIC-UDP",
                "DDOS attack-HOIC",
                "Brute Force -Web",
                "Brute Force -XSS",
                "SQL Injection",
                "Infilteration",
                "Bot"
            ]
        )
        label = encoded.transform(label)
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(
            feature.values, label, test_size=0.2, shuffle=True,stratify=label,random_state=state
        )

    def overwriteModel(self,classifier):
        scalar=StandardScaler()
        scalar.fit(self.x_train[1:])
        self.x_train[1:]=scalar.transform(self.x_train[1:])
        self.x_test[1:]=scalar.transform(self.x_test[1:])
        model = classifier.fit(self.x_train, self.y_train)
        predict = model.predict(self.x_test)
        print(str(classifier).replace("Classifier", "").replace("()",""))
        self.getScore(predict)
        joblib.dump(
                model,
                "training\\train\\model_{}.joblib".format(
                    str(classifier).replace("Classifier", "").replace("()","")
                ),
        )
    def overwriteAllModel(self):
        self.overwriteModel(RandomForestClassifier())
        self.overwriteModel(KNeighborsClassifier())
        self.overwriteModel(GaussianNB())
        self.overwriteModel(AdaBoostClassifier())
        self.overwriteModel(DecisionTreeClassifier())
    
    def getScore(self,predict):
        accuracy=metrics.accuracy_score(self.y_test,predict)
        recall=metrics.recall_score(self.y_test,predict,average='macro')
        precision=metrics.precision_score(self.y_test,predict,average='macro',zero_division=1)
        f1=metrics.f1_score(self.y_test,predict,average="macro",zero_division=1)
        print("\nAccuracy = {} %".format(accuracy*100))
        print("Recall = {} %".format(recall*100))
        print("Precision = {} %".format(precision*100))
        print("F1 = {} %".format(f1*100))

    def setupModel(self, classifier):
        if not os.path.exists(
            "training\\train\\model_{}.joblib".format(
                str(classifier).replace("Classifier", "").replace("()","")
            )
        ):
            scaler=StandardScaler()
            currentScaler=scaler.fit(self.x_train[1:])
            self.x_train[1:] = currentScaler.transform(self.x_train[1:])
            self.x_test[1:] = currentScaler.transform(self.x_test[1:])
            model = classifier.fit(self.x_train, self.y_train)
            predict = model.predict(self.x_test)
            print(str(classifier).replace("Classifier", "").replace("()",""))
            self.getScore(self.y_test,predict)
            # accuracy=metrics.accuracy_score(self.y_test,predict)
            # recall=metrics.recall_score(self.y_test,predict,average='macro')
            # precision=metrics.precision_score(self.y_test,predict,average='macro',zero_division=1)
            # f1=metrics.f1_score(self.y_test,predict,average="macro",zero_division=1)
            # print("\nAccuracy = {} %".format(accuracy*100))
            # print("Recall = {} %".format(recall*100))
            # print("Precision = {} %".format(precision*100))
            # print("F1 = {} %".format(f1*100))
            # self.crossValidate(classifier,self.x_train,self.y_train)
            joblib.dump(
                model,
                "training\\train\\model_{}.joblib".format(
                    str(classifier).replace("Classifier", "").replace("()","")
                ),
            )
        else:
            model = joblib.load(
                "training\\train\\model_{}.joblib".format(
                    str(classifier).replace("Classifier", "").replace("()","")
                )
            )
        return model

    def model_randomForest(self, feature):
        model = self.setupModel(RandomForestClassifier())
        model = convert(model, "pytorch")
        feature=torch.from_numpy(feature)
        model.to('cuda')
        result = model.predict(feature)
        prob = model.predict_proba(feature)
        return result,prob

    def model_KNN(self, feature):
        model = self.setupModel(KNeighborsClassifier())
        feature=torch.from_numpy(feature)
        result = model.predict(feature)     
        prob = model.predict_proba(feature)
        return result,prob

    def model_naiveBayes(self, feature):
        model = self.setupModel(GaussianNB())
        model = convert(model, "pytorch")
        feature=torch.from_numpy(feature)
        model.to('cuda')
        result = model.predict(feature)
        prob = model.predict_proba(feature)
        return result,prob

    def model_adaboost(self, feature):
        model = self.setupModel(AdaBoostClassifier())
        result = model.predict(feature)
        prob = model.predict_proba(feature)
        return result,prob
        # accuracy=metrics.accuracy_score(self.y_test,result)
        # print("\nAccuracy = {} %".format(accuracy*100))

    def model_decisionTree(self, feature):
        model = self.setupModel(DecisionTreeClassifier())
        model = convert(model, "pytorch")
        feature=torch.from_numpy(feature)
        model.to('cuda')
        result = model.predict(feature)
        prob = model.predict_proba(feature)
        return result,prob

    def crossValidate(self, model, feature, label, cvTime=7):
        result = cross_validate(
            estimator=model, X=feature, y=label, cv=cvTime, return_train_score=True
        )
        print("\nModel name : {}".format(str(model).replace("Classifier()", "")))
        print("Test score {} %".format(result["test_score"].mean() * 100))
        print("Train score {} %".format(result["train_score"].mean() * 100))

    # Require high time and resource to perform computation
    def getAllModelAccuracy(self):
        self.crossValidate(DecisionTreeClassifier(), self.x_train, self.y_train)
        self.crossValidate(AdaBoostClassifier(), self.x_train, self.y_train)


    def predictLabel(self,classXtrain,feature, selection="knn"):
        # pred = Learning()
        # pred.getSpecificDF()
        # pred.splitTrainTestData()
        scalar=StandardScaler()
        scalar.fit(classXtrain)
        feature[1:]=scalar.transform(feature[1:])
        if selection == "randomForest":
            return self.model_randomForest(feature)
        elif selection == "adaboost":
            return self.model_adaboost(feature)
        elif selection == "decisionTree":
            return self.model_decisionTree(feature)
        elif selection == "knn":
            return self.model_KNN(feature)
        elif selection == "naiveBayes":
            return self.model_naiveBayes(feature)

