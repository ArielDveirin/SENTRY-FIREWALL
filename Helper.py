from psutil import net_if_addrs
from re import fullmatch

GOOD = "good!"

def get_available_interfaces():
   return list(net_if_addrs().keys())

def check_interfaces(interface): 
  interfaces = get_available_interfaces()
  if interface not in interfaces:
     return "interface not valid" 
  return GOOD

def check_email(email):
   regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
   # pass the regular expression
   # and the string into the fullmatch() method
   if(fullmatch(regex, email)):
        return GOOD
   return "Invalid Email"

def validate(interface,email):
   email_msg = check_email(email)
   interface_msg = check_interfaces(interface)
   if interface_msg != GOOD or check_email(email) != GOOD:
      return (False , interface_msg , email_msg)
   return (True , interface_msg, email_msg)

