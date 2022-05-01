from os import system
from time import sleep
from scapy.all import AsyncSniffer
from scapy.layers.l2 import ARP
from threading import Thread
import NetworkMapper

BROADCAST = "ff:ff:ff:ff:ff"
ATTACK_NAME = "ARP spoofing"
ARP_REPLAY = 2

class Arp_spoof_detector():
    def __init__(self,arp_q, stop_event, under_arp_spoofing_event, db_wrapper,interface,locker):
        self.network_helper = NetworkMapper.Network_Mapper(interface)
        self.arp_q = arp_q
        self.interface = interface
        self.locker= locker
        self.db = db_wrapper
        self.under_arp_spoofing_event = under_arp_spoofing_event
        self.mac_black_list = list()
        self.stop_event = stop_event



    def start_detection(self):
    # store=False tells the sniff function to discard sniffed packets instead of storing them in memory
    # this is saving us memory beacuse our firewall runs a lot of time
     sniffer = AsyncSniffer(iface=self.interface,filter="arp", lfilter= lambda packet: packet[ARP].hwsrc.upper() not in self.mac_black_list, store=False, prn=self.identify_attack)
     sniffer.start()
     print("\nstarting arp poisoning detector")
     self.stop_event.wait() #waiting for the main thread
     if self.stop_event.is_set(): # if the main thread sent a singal
        sleep(0.06)
        sniffer.stop()
        self.stop_event.clear() #reset event flag
        print("\nexit successfully from arp poisoning detector")


    def add_to_database(self, attacker_mac, attacker_name,network_name):
      current_time = NetworkMapper.get_current_time()
      self.locker.acquire() #getting into critical section
      self.db.add(current_time,ATTACK_NAME, network_name,attacker_mac,attacker_name)
      self.locker.release()

    def block_attacker(self,mac):
      system(f"arptables -A INPUT  --source-hw --src-mac  {mac} -j DROP ")
      system(f"arptables -A OUTPUT  --target-hw --dst-mac {mac}  -j DROP")
      self.mac_black_list.append((mac.upper()))

    def process_attack(self, response_mac):
      src_ip = self.network_helper.get_ip_by_mac_address(response_mac)
      src_name = NetworkMapper.get_Host_name(src_ip)
      network_name = NetworkMapper.get_default_getaway()
      #warning other threads that there is an ongoiong arp spoof attack
      self.under_arp_spoofing_event.set() 
      self.add_to_database(response_mac,src_name, network_name)

    def identify_attack(self, packet):
      # checking if its an arp replay packet and making sure we don't check the attacker again
      if packet[ARP].op == ARP_REPLAY:
        try:
            # get the real MAC address of the sender
            real_mac = NetworkMapper.get_mac(packet[ARP].psrc)
            # get the MAC address from the packet
            response_mac = packet[ARP].hwsrc
            # if they are different, definitely there is an attack!
            if real_mac != response_mac:
                self.block_attacker(response_mac.lower())
                self.arp_q.put(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
                Thread(target=self.process_attack,args=(response_mac,),daemon=True).start()
        except IndexError:
            # if we couldn't find the mac address , might be a fake ip
            pass
