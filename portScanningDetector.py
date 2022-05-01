from lib2to3.pytree import convert
import socket
import time
from struct import *
import signal

global threewayhandshake, waiting, fullscandb, halfscandb, xmasscandb, nullscandb, finscandb, scannedports, blacklist


blacklist = []
fullscandb = {}
halfscandb = {}
blacklist = [], waiting = [], threewayhandshake = [], scannedports = {}

hostname = socket. gethostname()
LANip =  socket. gethostbyname(hostname)

def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def show_ports(signum, frm):
    for ips in scannedports:
        for single in scannedports[ips]:
            while (scannedports[ips].count(single) != 1):
                scannedports[ips].remove(single)
    print("\n\n")
    
    for ip in blacklist:
        if (scannedports.has_key(str(ip)) and ip != LANip):
            print
            "Attacker from ip " + ip + " scanned [" + ",".join(scannedports[ip]) + "] ports."


def threewaycheck(sip, dip, sport, dport, seqnum, acknum, flags):
    data = sip + ":" + str(sport) + "->" + dip + ":" + str(dport) + "_" + str(seqnum) + "_" + str(
        acknum) + "_" + "/".join(flags)
    if ("SYN" in flags and len(flags) == 1):
        if (seqnum > 0 and acknum == 0):
            waiting.append(
                str(seqnum) + "_" + str(acknum) + "_" + sip + ":" + str(sport) + "->" + dip + ":" + str(dport))
    elif ("SYN" in flags and "ACK" in flags and len(flags) == 2):
        for i in waiting:
            pieces = i.split("_")
            ack_old = pieces[1]
            seq_old = pieces[0]
            if (acknum == int(seq_old) + 1):
                del waiting[waiting.index(i)]
                waiting.append(
                    str(seqnum) + "_" + str(acknum) + "_" + sip + ":" + str(sport) + "->" + dip + ":" + str(dport))
                break

    elif ("ACK" in flags and len(flags) == 1):
        for i in waiting:
            pieces = i.split("_")
            ack_old = pieces[1]
            seq_old = pieces[0]
            if (seqnum == int(ack_old) and acknum == int(seq_old) + 1):
                index_i = waiting.index(i)
                del waiting[index_i]
                threewayhandshake.append(sip + ":" + str(sport) + "->" + dip + ":" + str(dport))
                break


def scancheck(sip, dip, sport, dport, seqnum, acknum, flags):
    global data, dataforthreewaycheck, dbdata, reverse
    #Just some data beutification to make it look better
    data = sip + ":" + str(sport) + "->" + dip + ":" + str(dport) + "_" + str(seqnum) + "_" + str(acknum) + "_" + "/".join(flags)
    dataforthreewaycheck = sip + ":" + str(sport) + "->" + dip + ":" + str(dport)
    revthreeway = dip + ":" + str(dport) + "->" + sip + ":" + str(sport)
    dbdata = sip + "->" + dip
    reverse = dip + "->" + sip

    if (halfconnectscan(sip, dip, sport, dport, seqnum, acknum, flags)):
        returned = halfconnectscan(sip, dip, sport, dport, seqnum, acknum, flags)
        if (isinstance(returned, (str))):
            print
            returned
        else:
            print (revthreeway + " Port Scanning Detected: [Style not Defined]:Attempt to connect closed port!" )
    elif (fullconnectscan(sip, dip, sport, dport, seqnum, acknum, flags)):
        returned = fullconnectscan(sip, dip, sport, dport, seqnum, acknum, flags)
        if (isinstance(returned, (str))):
            print(returned)


def fullconnectscan(sip, dip, sport, dport, seqnum, acknum, flags):
    if (scannedports.has_key(dip)):
        scannedports[dip].append(str(sport))
    else:
        scannedports[dip] = []
        scannedports[dip].append(str(sport))

    if (dataforthreewaycheck in threewayhandshake):
        if ("ACK" in flags and "RST" in flags and len(flags) == 2):
            if (fullscandb.has_key(dbdata)):
                counter = int(fullscandb[dbdata])
                if (counter >= 3):

                    if (str(dip) not in blacklist):
                        blacklist.append(str(dip))
                    return dip + ":" + str(dport) + "->" + sip + ":" + str(sport) + " => [Runtime Detection:] Full connect scan detected!" 
                else:
                    counter = counter + 1
                    fullscandb[dbdata] = str(counter)
            else:
                counter = 0
                fullscandb[dbdata] = str(counter)

    else:
        if ("SYN" in flags and len(flags) == 1):
            if (seqnum > 0 and acknum == 0):
                fullscandb[dbdata + "_SYN"] = str(seqnum) + "_" + str(acknum) + "_" + str(sport) + "_" + str(dport)

        elif ("RST" in flags and "ACK" in flags and len(flags) == 2):
            if (fullscandb.has_key(dip + "->" + sip + "_SYN")):
                manage = fullscandb[dip + "->" + sip + "_SYN"]
                pieces = manage.split("_")
                old_acknum = int(pieces[1])
                old_seqnum = int(pieces[0])
                if (seqnum == 0 and acknum == old_seqnum + 1):
                    if (fullscandb.has_key(dbdata)):
                        counter = int(fullscandb[dbdata])
                        if (counter >= 3):

                            if (str(dip) not in blacklist):
                                blacklist.append(str(dip))
                            return True
                        else:
                            counter = counter + 1
                            fullscandb[dbdata] = str(counter)
                    else:
                        counter = 0
                        fullscandb[dbdata] = str(counter)
    return False


def halfconnectscan(sip, dip, sport, dport, seqnum, acknum, flags):
    if (scannedports.has_key(dip)):
        scannedports[dip].append(str(sport))
    else:
        scannedports[dip] = []
        scannedports[dip].append(str(sport))

    if ("SYN" in flags and seqnum > 0 and acknum == 0 and len(flags) == 1):
        halfscandb[dbdata + "_" + str(seqnum)] = dbdata + "_SYN_ACK_" + str(seqnum) + "_" + str(acknum)
    elif ("RST" in flags and "ACK" in flags and len(flags) == 2):
        if (halfscandb.has_key(reverse + "_" + str(acknum - 1))):
            del halfscandb[reverse + "_" + str(acknum - 1)]
            if (str(dip) not in blacklist):
                blacklist.append(str(dip))

            return True
    elif ("SYN" in flags and "ACK" in flags and len(flags) == 2):
        if (halfscandb.has_key(reverse + "_" + str(acknum - 1))):
            del halfscandb[reverse + "_" + str(acknum - 1)]
            halfscandb[reverse + "_" + str(acknum)] = dbdata + "_RST_" + str(seqnum) + "_" + str(acknum)
    elif ("RST" in flags and len(flags) == 1):
        if (halfscandb.has_key(dbdata + "_" + str(seqnum))):
            if (str(dip) not in blacklist):
                blacklist.append(str(dip))

            return sip + ":" + str(sport) + "->" + dip + ":" + str(dport)  + " => [Runtime Detection:] Half connect(SYN scan) scan detected!"
    return False

now = time.time()
protocol_numb = {"1": "ICMP", "6": "TCP", "17": "UDP"}

s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

while True:
   
    try:
        packet = s.recvfrom(65565)
        packet = packet[0]
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        dest_mac = eth_addr(packet[0:6])
        source_mac = eth_addr(packet[6:12])
    except:
        pass

    if eth_protocol == 8:
        ip_header = packet[eth_length:20 + eth_length]

        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
        protocol = iph[6]
        if (str(iph[6]) not in protocol_numb.keys()):
            protocol_name = str(iph[6])
        else:
            protocol_name = protocol_numb[str(iph[6])]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        timestamp = time.time();
        elave = None

        # TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]
            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1];
            seq_numb = tcph[2]
            dest_numb = tcph[3]
            tcp_flags = convert(tcph[5])
            testdata = s_addr + ":" + str(source_port) + "->" + d_addr + ":" + str(dest_port)
            if (testdata not in threewayhandshake):
                threewaycheck(s_addr, d_addr, source_port, dest_port, seq_numb, dest_numb, tcp_flags)

            scancheck(s_addr, d_addr, source_port, dest_port, seq_numb, dest_numb, tcp_flags)
            try:
                signal.signal(signal.SIGINT, show_ports)
            except:
                pass
