from functools import total_ordering
import subprocess

def main():
    inputVals = inputs()
    #inputVals['path'] = "C:\Users\Jon\OneDrive - Linköpings universitet\Kurser\TDTS11 - Datornät och internetprotokoll\Laborationer\Assignment 4\task 3\Question 2\2. xinhuanet.com\trace_xihuanet.com.pcapng"
    #inputVals['ipv6'] = "2001:6b0:17:fc09:549e:2d94:15d3:f3cb"
    #inputVals['ipv4'] = "10.253.235.173"
    ttls = sharker(inputVals['path'], inputVals['ipv6'], inputVals['ipv4'])
    avghops = calcAvgHopLen(ttls['ttl'], ttls['hoplimit'])

    print("Avgrage hop length: ", avghops)


def sharker(path, ipv6, ipv4):
    ttl = subprocess.check_output(["tshark", "-r", path, '-T', 'fields', '-e', 'ip.ttl', '-Y', '!ip.src eq '+ipv4+' && !ipv6.src eq '+ipv6], shell=True)
    ttl = ttl.split(b'\r\n')
    ttl = [i.decode('utf-8') for i in ttl]
    ttl = list(filter(None, ttl))
    ttl = list(map(int, ttl))
    
    hoplimit = subprocess.check_output(["tshark", "-r", path, '-T', 'fields', '-e', 'ipv6.hlim', '-Y', '!ip.src eq '+ipv4+' && !ipv6.src eq '+ipv6], shell=True)
    hoplimit = hoplimit.split(b'\r\n')
    hoplimit = [i.decode('utf-8') for i in hoplimit]
    hoplimit = list(filter(None, hoplimit))
    hoplimit = list(map(int, hoplimit))

    return {
        "ttl": ttl,
        "hoplimit": hoplimit
    }

def calcAvgHopLen(ttl, hoplimit):
    STD_TTL_VALS = [255, 64, 128]

    hops = list()

    for i in ttl:
        if i <= 64:
            hops.append(64 - i)
        elif i > 64 and i <= 128:
            hops.append(128 - i)
        elif i > 128 and i <= 255:
            hops.append(255 - i)
            
    for i in hoplimit:
        if i <= 64:
            hops.append(64 - i)
        elif i > 64 and i <= 128:
            hops.append(128 - i)
        elif i > 128 and i <= 255:
            hops.append(255 - i)

    hopsLen = len(hops)
    totalHops = 0

    for i in hops:
        totalHops += i

    return round((totalHops / hopsLen), 2) 

def inputs():
    path = input("Path to tracefile: ")
    ipv4 = input("Your ipv4 address in trace: ")
    ipv6 = input("Your ipv6 address in trace: ")
    return {
        "path": path, 
        "ipv6": ipv6,
        "ipv4": ipv4
    }


main()