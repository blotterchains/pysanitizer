"""
author:uncle wizard <reza divsalar>
"""


# import os to making subproccess and use file command to know 
# what extentions is used for binary files
import os
import subprocess
# import global modules and constants variables 
from constants import FilterAllowed , FilterDir , terminalColors , NotAllowedScripts , NotAllowedLanguageScripts
# import oletools to analyse office files
try:
    import olefile
except:
    os.system("pip3 install oletools")
# import guesslang to detect what language inside text files that cant detect with filterFiles class object 
try:
    import guesslang
except:
    print("please install guesslang from\n https://github.com/yoeo/guesslang \n dont use pip to install because of dependency problem with latest version of ternsorflow in python 3.9 and later")
# module class for filtering file formats
class filterFiles:
    def __init__(self,debug=False):
        self.filePath=None
        self.malFiles=[]
        self.debug=debug
        if(self.debug):
            print(
            terminalColors.WARNING +
            "this is our allowed file types\nwe use mimetype to show our extentions\n"+
            terminalColors.ENDC +
            terminalColors.OKGREEN + 
            terminalColors.BOLD +
            str(FilterAllowed) +
            terminalColors.ENDC
        )
    # return mimetype for future use like using in script check file mimetype
    def currentMimeType(self):
        return self.mimeType
    # get the file Info
    # this function must call after calling filterWithPath
    def fileInfo(self,fail=False):
        # check is file path not null
        if(self.filePath==None):
            print(
                terminalColors.FAIL +
                "you don't enter path of the file" +
                terminalColors.ENDC
            )
        else:
            #check size
            fileSize=os.path.getsize(self.filePath)
            # check that they send us a fail signal or not
            if(fail==False):
                print(
                    terminalColors.OKCYAN +
                    terminalColors.BOLD +
                    "file:%s \nsize:%sKb\nmimeType:%s\n-------"%(
                        self.filePath,
                        fileSize*10**-3,
                        self.mimeType
                    )+
                    terminalColors.ENDC
                )
            else:
                print(
                    terminalColors.FAIL +
                    terminalColors.BOLD +
                    "this is not an allowed file format\nfile:%s \nsize:%sKb\nmimeType:%s\n-------"%(
                        self.filePath,
                        fileSize*10**-3,
                        self.mimeType
                    )+
                    terminalColors.ENDC
                )
    # saniztize file with allowed file format mimetype
    def filterWithPath(self,path):
        self.filePath=path
        # check mimefile type
        mimeTypeOutput=subprocess.run(["file", "--mime-type", str(self.filePath)], capture_output=True).stdout
        self.mimeType=mimeTypeOutput[mimeTypeOutput.find(b": ")+2:mimeTypeOutput.find(b"\n")].decode("utf-8")
        if(self.debug):
            # check mime type is allowed or not
            if(self.mimeType in FilterAllowed):self.fileInfo()
            # send fail signal
            else:
                self.malFiles.append(self.filePath)
                self.fileInfo(fail=True)
        else:
            if(self.mimeType in FilterAllowed):pass
            else:self.malFiles.append(self.filePath)
    # sanitize with os walk and scan all files inside specified folder in constants.py
    def filterScanFolder(self):
        for root , __directory , filenames in os.walk(FilterDir):
            for f in filenames:
                self.filterWithPath(os.path.join(root,f))
    def showFilteredFiles(self):
        return self.malFiles
    
class OLEOfficeDocument:
    def __init__(self,debug=False):
        self.debug=debug
        self.malFiles=[]
        self.filePath=None
        if(self.debug):
            print(
                terminalColors.WARNING +
                terminalColors.BOLD +
                "office ole activated" +
                terminalColors.ENDC
            )
    def checkWithPath(self,path):
        self.filePath=path
        if(self.debug):
            if(olefile.isOleFile(self.filePath)):
                print(
                    terminalColors.FAIL +
                    terminalColors.BOLD +
                    "macro file detected in this path:%s\n-------"%(
                        self.filePath
                    )+
                    terminalColors.ENDC
                )
                self.malFiles.append(self.filePath)
            else:pass
        else:
            if(olefile.isOleFile(self.filePath)):
               
                self.malFiles.append(self.filePath)
            else:pass
    def OLEScanFolder(self):
        for root , __directory , filenames in os.walk(FilterDir):
            for f in filenames:
                self.checkWithPath(os.path.join(root,f))
    def showOLEFiles(self):
        return self.malFiles
# filter all scripting languages and detect malucios code in html and hta files
class scriptFilter:
    def __init__(self,debug=False):
        self.debug=debug
        self.malFiles=[]
        self.filePath=None
        if(self.debug):
            print(
                terminalColors.WARNING +
                terminalColors.BOLD +
                "filter text based files with AI to detect malicious scripts" +
                terminalColors.ENDC
            )
    def detectWithPath(self,path):
        self.filePath=path
        # get file mime type with use of filter file class object
        # use this to get mime type it is not filter any kind of file format
        mimeType=filterFiles()
        mimeType.filterWithPath(self.filePath)
        mimeType=mimeType.currentMimeType()
        # read script
        rawScript=open(self.filePath,"rb")
        if(self.debug):
            if(mimeType in NotAllowedScripts):
                # detect script language
                # we check batch and powershell
                if(mimeType == "text/plain" or mimeType == "text/x-msdos-batch"):
                    
                    guess=guesslang.Guess()
                    lang=guess.language_name(rawScript.read())
                    if(lang in NotAllowedLanguageScripts):
                        print(
                            terminalColors.FAIL+
                            "malicious script found on %s \n scripting languge is:%s"%(
                                self.filePath,
                                lang) +
                            terminalColors.ENDC
                        )
                        self.malFiles.append(self.filePath)
                # detect are we have VBA in our html files
                # this is very use full when attacker use HTA file format
                # to initialize attack
                elif(mimeType == "text/html"):
                    scriptReader=rawScript.read()
                    if(b'type="text/vbscript"' in scriptReader):
                        print(
                        terminalColors.FAIL+
                        "malicious vba found in html at %s"%(self.filePath)+
                        terminalColors.ENDC
                        )
                        self.malFiles.append(self.filePath)
                    else:pass
            else:pass
        # all things from top withot printing anything
        else:
            if(mimeType in NotAllowedScripts):
                
                if(mimeType == "text/plain" or mimeType == "text/x-msdos-batch"):
                    guess=guesslang.Guess()
                    lang=guess.language_name(rawScript.read())
                    if(lang in NotAllowedLanguageScripts):
                        self.malFiles.append(self.filePath)
                elif(mimeType == "text/html"):
                    scriptReader=rawScript.read()
                    if(b'type="text/vbscript"' in scriptReader):
                        self.malFiles.append(self.filePath)
                    else:pass
            else:pass
        rawScript.close()
    def detectScanFolder(self):
        for root , __directory , filenames in os.walk(FilterDir):
            for f in filenames:
                self.detectWithPath(os.path.join(root,f))
    def showDetectedFiles(self):
        return self.malFiles
