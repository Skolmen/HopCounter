import subprocess

def main():
    paths, tcpStreams = inputs()
    
    #inputVals['path'] = "C:\Users\Jon\OneDrive - Linköpings universitet\Kurser\TDTS11 - Datornät och internetprotokoll\Laborationer\Assignment 4\task 3\Question 2\2. xinhuanet.com\trace_xihuanet.com.pcapng"
    
    for path, tcpStream in zip(paths, tcpStreams):
        allcontent = sharker(path, tcpStream)
        allcontent = getContentType(allcontent)

        print("\nFor trace " + path)
        print("The drag along content types are: ")
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

    totOfTraces = int(input("How many traces do you want to check?"))

    paths = list()
    tcpStreams = list()

    for i in range(totOfTraces):
        paths.append(input("\nPath to tracefile: "))
        tcpStreams.append(input("TCP-stream id of the inital request: "))

    return paths, tcpStreams


main()