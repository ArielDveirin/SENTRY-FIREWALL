from os import system
from time import sleep
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP

import NetworkMapper

# [addres: syn, ack]
addr_dict = dict()
ip_black_list = set()
MAX_SYNS = 5
MIN_ACKS = 1
ATTACK_NAME = "syn flood"
SYN = 0x02
SYN_ACK = 0x12
QUEUE_NUM = 1

class Syn_flood_detector():
 def __init__(self,messanger , stop_event , under_arp_spoofing_event, db_wrapper , interface,locker):
    self.stop_event = stop_event
    self.db = db_wrapper
    self.locker = locker
    self.under_arp_spoofing_event = under_arp_spoofing_event
    self.interface = interface
    self.messanger_q = messanger


    
 # a function to check for an attack
 # if a source sends a lot of SYN, but does not send back ACK, he's an attacker
 def checkForAttack(self, packet):
    source = packet["IP"].src
    if source in addr_dict:
        # check if the source has been sending a lot of SYN's.
        if addr_dict[source][0] > MAX_SYNS and addr_dict[source][1] < MIN_ACKS:
            return True
    return False


 # helper methods for processPacket
 def count_syn_packet(self, addr):
    if addr in addr_dict:
        addr_dict[addr] = (addr_dict[addr][0] + 1, addr_dict[addr][1])
    else:
        addr_dict[addr] = (1, 0)


 def count_syn_ack_packet(self, addr):
    if addr in addr_dict:
        addr_dict[addr] = (addr_dict[addr][0], addr_dict[addr][1] + 1)
    else:
        addr_dict[addr] = (0, 1)

 def add_to_database(self,attacker_mac,attacker_name, network_name):
   current_time = NetworkMapper.get_current_time()
   self.locker.acquire()
   self.db.add(current_time,ATTACK_NAME, network_name,attacker_mac,attacker_name)
   self.locker.release()

 def notify_and_block(self, ip):
    current_time = NetworkMapper.get_current_time()
    self.messanger_q.put(f"Your'e under SYN Flood attack! from {ip} at {current_time}")
    command = f"iptables -I INPUT -s {ip} -p tcp -m conntrack --ctstate RELATED,ESTABLISHED  -j DROP"
    system(command)
    ip_black_list.add(ip)
    try:
      del addr_dict[ip]
    except Exception as e:
       print(e)


 def attacker_callback(self, scapy_packet):
    src_ip = scapy_packet["IP"].src
    self.notify_and_block(src_ip)
    src_mac, src_name,network_name = NetworkMapper.get_info_on_atatcker(src_ip, self.under_arp_spoofing_event)
    self.add_to_database(src_mac, src_name,network_name)

    

 def processPacket(self, pkt):
    flags = pkt["TCP"].flags

     # if SYN or SYN-ACK, respond accordingly
    if flags == SYN:
            self.count_syn_packet(pkt["IP"].src)

    elif flags == SYN_ACK:
            self.count_syn_ack_packet(pkt["IP"].dst)

    if self.checkForAttack(pkt):
        self.attacker_callback(pkt)



 def start_detection(self):
     print("\nstarting syn flood detector")
    # store=False tells the sniff function to discard sniffed packets instead of storing them in memory
    # this is saving us memory beacuse our firewall runs a lot of time
     sniffer = AsyncSniffer(iface=self.interface,filter='tcp', lfilter= lambda x: x.haslayer(IP) and x[IP].src not in ip_black_list, store=False, prn=self.processPacket)
     sniffer.start()
     self.stop_event.wait()
     if self.stop_event.is_set():
        sleep(0.06)
        sniffer.stop()
        self.stop_event.clear()
        print("\nexit successfully from syn flood detector")



