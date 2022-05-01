from datetime import datetime
from socket import gethostbyaddr ,gethostbyname ,gethostname
from netifaces import gateways , ifaddresses
from dns.resolver import Resolver
from ipcalc import IP 
from subprocess import Popen , PIPE
from getmac import get_mac_address

BROADCAST = "ff:ff:ff:ff:ff"
TIMEOUT = 10


#Helpers
def get_default_getaway():
    getaway_ip = gateways()[2][0][0]
    return get_Host_name(getaway_ip)

def get_local_ip():
    return gethostbyname(gethostname())

def get_dns_servers():
    return Resolver().nameservers

def get_current_time():
   now = datetime.now()
   dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
   dt_string.replace('/', '-')
   return dt_string


def get_Host_name(ip):
     try:
        host_name = gethostbyaddr(ip)[0]
        return host_name
     except:
         raise IndexError("host name could not be found")

def get_mac(ip_addr):
    mac_addr =  get_mac_address(ip=ip_addr,network_request=True)
    if mac_addr == "00:00:00:00:00:00" or mac_addr == None:
        raise IndexError("mac address could not be found")
    return mac_addr



def get_info(ip):
    return  get_mac(ip) , get_Host_name(ip) ,get_default_getaway()

def get_info_on_atatcker(ip, under_arp_spoofing_event):
   try:
    mac_address , host_name , router_name = get_info(ip)
   except:
       #If the operation fails it may be because of an arp poisoning attack that is happening now
       under_arp_spoofing_event.wait(timeout=TIMEOUT)
       #If the failure was not beacuse of an arp poisoning attack
       if not under_arp_spoofing_event.is_set():
          host_name = "null"
          router_name = "null"
       else:
        #if the attack has stop then we try again 
        under_arp_spoofing_event.clear()
        mac_address , host_name , router_name = get_info(ip)
   return mac_address , host_name , router_name

    

class Network_Mapper:
    def __init__(self, interface):
        #stats is holding some important network information
        stats = ifaddresses(interface)[2][0]
        self.interface = interface
        self.ip = stats.get('addr')
        self.mask = stats.get('netmask')
        self.network_range = self.get_network_mask()

    def get_ip_by_mac_address(self,mac_addr):
     network_mask = self.get_network_mask()
     # we dont want the verbose output of the command so we redirect it to /dev/null
     # awk to return the second item in the output
     command = "nmap -sP " + network_mask + " >/dev/null && arp -an | grep " + mac_addr + " | awk '{print $2}'"
     result = Popen(command, shell=True, stdout=PIPE)
     ip_addr = result.stdout.read()
     ip_addr = ip_addr[1: len(ip_addr) - 2]
     return ip_addr

    def get_network_mask(self):
     address = IP(self.ip, mask=self.mask)  # returns an ip object
     network_range = str(address.guess_network())  # returns up at this range specific network
     return network_range

