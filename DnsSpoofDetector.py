import json , os
from time import time
from time import sleep
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP
from collections import defaultdict
from scapy.layers.dns import DNSRR, DNS

import NetworkMapper

IP_ADDRESS = 1
ATTACK_NAME = "Dns spoof"
INTERVAL = 5

class Dns_spoof_detector():
    def __init__(self,messanger,stop_event, under_arp_spoofing_event, db_wrapper,interface,locker):

     self.messanger = messanger
     self.stop_event = stop_event
     self.interface =interface
     self.under_arp_spoofing_event = under_arp_spoofing_event
     self.db = db_wrapper
     self.locker = locker
     self.to_be_deleted = dict()
     self.local_ip = NetworkMapper.get_local_ip()
     self.dns_servers = NetworkMapper.get_dns_servers()
     #we use the default dict so we can have duplicate keys in it
     self.dictionary_of_answers = defaultdict(set)
     self.ip_black_list = set()






    def clean_answers(self , answers_to_be_deleted):
      """
      This function deletes the dns replays dictionary

      :param self:  represents the instance of the class
      :param answers_to_be_deleted: list of dns replays taht will be deleted
      :return: None
      """ 
      for ans in answers_to_be_deleted:
        if ans in self.dictionary_of_answers:
          del self.dictionary_of_answers[ans]


    def check_dictionaries(self):
      """
      This function checks if the dns replays were stored more then 5 seconds

      :param self:  represents the instance of the class
      :return: None
      """ 
      elapsed_time = time() - INTERVAL
      replays_to_be_deleted = list()
      for request_id in self.to_be_deleted.keys():
        request_time = self.to_be_deleted[request_id]
        if request_time < elapsed_time:
            replays_to_be_deleted.append(request_id)
      self.clean_answers(replays_to_be_deleted)



    def store_answer(self, dns_layer, ip_layer):
      """
      This function takes the urls from the dns replay packet and stores 
      them on teh dictionary_of_answers

      :param self:  represents the instance of the class
      :param dns_layer:  holding the dns layer details
      :param ip_layer: holding the ip layer details 
      :return: None
      """
      if ip_layer.dst == self.local_ip:
        # the count variable is holding the number of answers we got from our request
        count = dns_layer.ancount

        if count == 0:  # if we didn't got an answer
            ans = "null"
        elif count == 1:  # if we got only one answer
            ans = dns_layer.an.rdata  # collecting the answer from the dns packet
        else:
            ans = str()
            callback = dns_layer.an
            # this loop is collecting all the answers that the dst ip gave to us
            for i in range(count):
                if callback.type == IP_ADDRESS:
                    ans = callback.rdata + "," + ans
                callback = callback.payload
            ans = ans[:len(ans) - 1]  # removes the last comma
        item = (ip_layer.src, ans)
        self.dictionary_of_answers[dns_layer.id].add(item)


    def get_details(self,dns_layer):
      """
      This function takes data from the dns_layer object such as:
      request id , request url etc.. and puts it in a dictionary

      :param self:  represents the instance of the class
      :param dns_layer:  holding the dns layer details
      :return: dictionary  
      """
      url = dns_layer.qd.qname.decode()
      url = url[:len(url) - 1]
      data_set = dict()
      data_set["Number of answers"] = len(self.dictionary_of_answers[dns_layer.id])
      data_set["request id"] = dns_layer.id
      data_set["requested url"] = url
      return data_set

    def check_for_attack(self, dns_layer):
      """
      This function checks whever or not there were two answer
      for the current requested url and if there is , alerts 
      to the main thread with a queue
      :param self:  represents the instance of the class
      :param dns_layer:  holding the dns layer details
      :return: boolean 
      """
      if len(self.dictionary_of_answers[dns_layer.id]) > 1: #if we got more then one answer
        counter = 1
        list_of_answers = list()
        attack_details = self.get_details(dns_layer) 
        for answer_callback in self.dictionary_of_answers[dns_layer.id]:
            if answer_callback[0] not in self.dns_servers: # if the responder is not a trusted source
                self.messanger.put(f"Your'e under Dns spoof attack! from {answer_callback[0]}")
                self.ip_black_list.add(answer_callback[0]) # add the responder to the black list
            answer = 'AN' + str(counter) + ": " + answer_callback[1] + " from: " + answer_callback[0]
            list_of_answers.append(answer)
            counter += 1
        attack_details["answers"] = list_of_answers
        details_on_attack = json.dumps(attack_details)
        self.messanger.put(details_on_attack)
        return True

      return False

      
    def block(self, ip,dns_layer):
      """
      This function blocks the attacker with iptables

      :param self:  represents the instance of the class
      :param dns_layer:  holding the dns layer details
      :param ip:  represent the attacker ip
      :return: none  
      """
      command = f"iptables -I INPUT -s {ip} -p udp --sport 53 -m conntrack --ctstate RELATED,ESTABLISHED -j DROP"
      os.system(command)
      try:
       self.ip_black_list.add(ip)
       del self.dictionary_of_answers[dns_layer.id]
      except Exception as e:
       print(e)
      
    def add_to_database(self,attacker_mac,attacker_name, network_name):
      """
      This function adds the given parameters to the databse

      :param self:  represents the instance of the class
      :param attacker_mac: mac address of the attacker
      :param attacker_name: attacker host name
      :param network_name: network host name
      :return: none  
      """
      current_time = NetworkMapper.get_current_time()
      self.locker.acquire()
      self.db.add(current_time,ATTACK_NAME, network_name,attacker_mac,attacker_name)
      self.locker.release()

    def attacker_callback(self,src_ip, dns_layer):
      """
      This function handles the process notifing and blocking
      the attacker

      :param self:  represents the instance of the class
      :param dns_layer:  holding the dns layer details
      :param src_ip:  represent the attacker ip
      :return: none  
      """
      self.block(src_ip,dns_layer)
      src_mac, src_name,network_name = NetworkMapper.get_info_on_atatcker(src_ip, self.under_arp_spoofing_event)
      self.add_to_database(src_mac, src_name,network_name)

    def processPacket(self , pkt):
      dns_layer = pkt.getlayer(DNS)
      ip_layer = pkt.getlayer(IP)
      self.check_dictionaries()
      if pkt.haslayer(DNSRR): #if its a dns replay
           self.store_answer(dns_layer, ip_layer)
      else: #if this is a dns request we store its id and request time on a dictionary
          self.to_be_deleted[dns_layer.id] = int(time())

      if self.check_for_attack(dns_layer):
        src_ip = pkt["IP"].src
        self.attacker_callback(src_ip, dns_layer)


    def start_detection(self):
      print("\nstarting dns spoof detector")
    # store=False tells the sniff function to discard sniffed packets instead of storing them in memory
    # this is saving us memory beacuse our firewall runs a lot of time
      sniffer = AsyncSniffer(iface=self.interface,filter='udp',lfilter= lambda x: x.haslayer(DNS) and x.haslayer(IP) 
      and x["IP"].src not in self.ip_black_list, store=False, prn=self.processPacket)
      sniffer.start()
      self.stop_event.wait()
      if self.stop_event.is_set():
        sleep(0.06)
        sniffer.stop()
        self.stop_event.clear()
        print("exit successfully from dns spoof detector")
        

