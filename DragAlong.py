from functools import total_ordering
import subprocess

def main():
    paths, ipv4s, ipv6s, tcpStreams = inputs()

    for path, ipv4, ipv6, tcpStream in zip(paths, ipv4s, ipv6s, tcpStreams):
        initalRqttls = sharker(path, ipv6, ipv4, tcpStream, True)
        dragAlongttls = sharker(path, ipv6, ipv4, tcpStream, False)
        
        print("\nFor the tracefile: " + path)
        print("Avgrage hop length for dragalong: ", calcAvgHopLen(dragAlongttls['ttl'], dragAlongttls['hoplimit']))
        print("Avgrage hop length for inital request: ", calcAvgHopLen(initalRqttls['ttl'], initalRqttls['hoplimit']))


def sharker(path, ipv6, ipv4, tcpStream, initalRq):
    validInitalRq = [True, False]
    if initalRq not in validInitalRq:
        raise ValueError("initalRq must be True or False")

    cmdTsharkTTL = ["tshark", "-r", path, '-T', 'fields', '-e', 'ip.ttl', '-Y', '!ip.src eq ' + ipv4 + ' && !ipv6.src eq ' + ipv6 + ' && !tcp.stream eq ' + tcpStream]
    cmdTsharkHopLimit = ["tshark", "-r", path, '-T', 'fields', '-e', 'ipv6.hlim', '-Y', '!ip.src eq ' + ipv4 + ' && !ipv6.src eq ' + ipv6 + ' && !tcp.stream eq ' + tcpStream]

    if (initalRq):
        cmdTsharkTTL = ["tshark", "-r", path, '-T', 'fields', '-e', 'ip.ttl', '-Y', '!ip.src eq '+ipv4+' && !ipv6.src eq ' + ipv6 + ' && tcp.stream eq ' + tcpStream]

    if (initalRq):
        cmdTsharkHopLimit = ["tshark", "-r", path, '-T', 'fields', '-e', 'ipv6.hlim', '-Y', '!ip.src eq ' + ipv4 + ' && !ipv6.src eq ' + ipv6 + ' && tcp.stream eq ' + tcpStream]

    ttl = subprocess.check_output(cmdTsharkTTL, shell=True)
    ttl = ttl.split(b'\r\n')
    ttl = [i.decode('utf-8') for i in ttl]
    ttl = list(filter(None, ttl))
    ttl = list(map(int, ttl))
    
    hoplimit = subprocess.check_output(cmdTsharkHopLimit, shell=True)
    hoplimit = hoplimit.split(b'\r\n')
    hoplimit = [i.decode('utf-8') for i in hoplimit]
    hoplimit = list(filter(None, hoplimit))
    hoplimit = list(map(int, hoplimit))

    return {
        "ttl": ttl,
        "hoplimit": hoplimit
    }

def calcAvgHopLen(ttl, hoplimit):
    STD_TTL_VALS = [255, 128, 64]

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

    totalOfTraces = int(input("How many traces do you want to check? "))

    paths = list()
    ipv4s = list()
    ipv6s = list()
    tcpStreams = list()

    for i in range(totalOfTraces):
        print("\nInfo for the " + str((i + 1)) + " trace")
        paths.append(input("Path to tracefile: "))
        ipv4s.append(input("Your ipv4 address in trace: "))
        ipv6s.append(input("Your ipv6 address in trace: "))
        tcpStreams.append(input("TCP-Stream id of inital request: "))
    
    return paths, ipv4s, ipv6s, tcpStreams


main()