#!/bin/python
import sys
import os
import datetime

class findip4block:
    def __init__(self,NumberReq):
         self.NumberReq = int(NumberReq)

    def readinf(self):
        m=[]
        count=0
        with open("px") as fp:
            Lines = fp.readlines()
            for line in Lines:
                count += 1
                m.append( line.strip().split("["))
        return m

    def conv(self,timeInp):
        timeinp=str(timeInp)
        try:
            data_format = datetime.datetime.strptime(timeinp,"%d/%B/%Y:%H:%M:%S")
        except ValueError:
            return timeInp
        unix_time = datetime.datetime.timestamp(data_format)
        return int(unix_time)


    #count the number of the requests for every ip
    def CRFI(self):#count rerquests for IPS
        DataList=self.readinf()
        for i in range(len(DataList)):
            DataList[i].append(len(DataList[i])-1)#The number of requests from each IP is added to the bottom of each list
        return DataList

    def convtounix(self):
        DataList=self.CRFI()
        n=[]
        for i in range(len(DataList)):
            if(self.NumberReq<=int(DataList[i][-1])):
                #print(self.NumberReq,DataList[i][-1],n)
                n.append(list(map(self.conv,DataList[i][:])))#convert timestamp to unix t
        return n

    #The first request is equal to zero
    #The rest of the time is calculated relative to the first request. (unit:seconds)
    def FRTZ(self):#First Request to zero
        w=[]
        DataList=self.convtounix()
        for i in self.convtounix():
            v=[x-min(i[1:-1]) for x in i[1:-1]]
            v.sort()
            v.insert(0,i[0])
            w.append(v)
        return w

    # find destances grater than 60s
    def FindTimeStartReq(self):
        I=self.FRTZ()
        SepIndx=[]
        o=[]
        for i in I[:]:
            pv=0
            for j in i[1:]:
                if(j-pv>60):
                    SepIndx.append(i.index(j))#indexj
                pv=j
            SepIndx.insert(0,0)
            o.append(SepIndx[:])
            SepIndx=[]
        return o

    def FindGreatSender(self):
        ix=self.FindTimeStartReq()
        Data=self.FRTZ()
        acc=0
        ll=0
        finalout=[]
        for i in ix:
            acc=0
            for j in i:
                    acc=0
                    for ii in Data[ll][j+1:]:
                        if(ii<60 +Data[ll][j+1]):
                            acc+=1
                            if(acc>self.NumberReq):
                                #print("block",ll,Data[ll][0])
                                finalout.append(Data[ll][0])
                                acc=0
                                break
            ll+=1
        return list(set(finalout))

r=findip4block(sys.argv[1])
w=r.FindGreatSender()
for i in w:
    os.popen('sudo iptables -I INPUT -s' + str(i) + '-j DROP')
    print("Block :",i)

os.popen('sudo iptables-save > /etc/sysconfig/iptables')
