from queue import Queue , Empty
from os import system 
from time import sleep
from threading import Thread , Event , Lock
from ArpSpoofDetector import Arp_spoof_detector
from DnsSpoofDetector import Dns_spoof_detector
from SMTP_Communicator import SmtpCommunicator
from SynFloodDetector import Syn_flood_detector
from CountryBlocker import Country_Blocker
from SqlManager import SQL_Manager
#from portScanningDetector import portScanningDetector

alerts = list()
alerts_flag = Event()
Arp_event = Event()
Syn_event = Event()
Dns_event = Event()
under_arp_spoofing_event = Event()
locker = Lock()

def print_alerts(q):
   while not alerts_flag.is_set():
     try:
      item = q.get(block=True, timeout=0.05)
      alerts.append(item)
      q.task_done()
     except Empty:
         pass
   system("iptables -F")
   system("arptables -F")



class serverLogic():
   def __init__(self, interface,email,password):
    messanger_queue = Queue()
    self.db_manager = SQL_Manager()
    self.counrty_blocker = Country_Blocker()
    self.Smtp_communicator = SmtpCommunicator(email,password)
    self.arp_detecor = Arp_spoof_detector(messanger_queue,Arp_event, under_arp_spoofing_event, self.db_manager,interface, locker)
    self.dns_detector = Dns_spoof_detector(messanger_queue,Dns_event, under_arp_spoofing_event, self.db_manager,interface,locker)
    self.syn_detector = Syn_flood_detector(messanger_queue , Syn_event, under_arp_spoofing_event, self.db_manager,interface, locker)
    
    self.PortScanningDetector = None
    
    self.messanger =  Thread(target=print_alerts,args=(messanger_queue,),daemon=True)
    self.messanger.start()
   
   def get_manager(self):
      return self.db_manager

   def shutdown(self):
      Dns_event.set()
      Arp_event.set()
      Syn_event.set()
      alerts_flag.set()
      self.messanger.join()
      sleep(1)

   def activateArpSpoofDetector(self):
      Thread(target=self.arp_detecor.start_detection,daemon=True).start()
   def activateDnsSpoofDetector(self):
         Thread(target=self.dns_detector.start_detection,daemon=True).start()
   def activateSynFloodDetector(self):
        Thread(target=self.syn_detector.start_detection,daemon=True).start()

   def PortScanningDetector(self):
        Thread(target=self.port_detector.start_detection,daemon=True).start()

   def activateCountryBlocker(self, countryName):
      return self.counrty_blocker.block(countryName)

   def activateCountryUnBlocker(self, countryName):
      return self.counrty_blocker.unblock(countryName)

   def disableDnsSpoofDetector(self):
      Dns_event.set()
   def disableArpSpoofDetector(self):
      Arp_event.set()
   def disableSynFloodDetector(self):
      Syn_event.set()

   def get_data(self):
      return alerts
      
      


        

