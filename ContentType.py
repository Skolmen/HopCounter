from functools import total_ordering
import subprocess

def main():
    inputVals = inputs()
    #inputVals['path'] = "C:\Users\Jon\OneDrive - Linköpings universitet\Kurser\TDTS11 - Datornät och internetprotokoll\Laborationer\Assignment 4\task 3\Question 2\2. xinhuanet.com\trace_xihuanet.com.pcapng"
    allcontent = sharker(inputVals['path'], inputVals['tcpStream'])
    allcontent = getContentType(allcontent)

    print("\nThe drag along content types for the trace are:")
    for i in allcontent:
        print(i)


def sharker(path, tcpStream):

    cmdTshark = ["tshark", "-r", path, '-T', 'fields', '-e', 'http.content_type', '-Y', 'http.content_type && !tcp.stream eq '+ tcpStream]

    contentTypes = subprocess.check_output(cmdTshark, shell=True)

    contentTypes = contentTypes.split(b'\r\n')
    contentTypes = [i.decode('utf-8') for i in contentTypes]
    contentTypes = list(filter(None, contentTypes))

    return contentTypes

def getContentType(allContent):
    return list(dict.fromkeys(allContent))

def inputs():
    path = input("Path to tracefile: ")
    tcpStream = input("TCP-stream id of the inital request: ")
    return {
        "path": path,
        "tcpStream": tcpStream
    }


main()