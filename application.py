from flask import Flask, render_template, request
from SqlManager import SQL_Manager
from logic import  serverLogic
from Helper import validate , get_available_interfaces
from os import geteuid

SentryApp = Flask(__name__)
SentryApp.config['SECRET_KEY'] = 'ArielAdam'
server = None
Syn = 'off'
Arp = 'off'
Dns = 'off'
Port = 'off'

@SentryApp.route('/',  methods=['GET', 'POST'])  
def MainPage():  
   return render_template('landingPage.html')

@SentryApp.get('/landingPage')
def landingPage():
   return render_template('landingPage.html')
@SentryApp.get('/')  
def main_page():
   interfaces = get_available_interfaces()
   return render_template('start.html',interfaces=interfaces)

@SentryApp.get('/aboutus')
def about_us():
   return render_template('aboutus.html')

@SentryApp.get('/protections')
def protections():
   return render_template('protections.html')

@SentryApp.route('/topMenu')  
def top_frame():  
      return render_template('topMenu.html')

@SentryApp.route('/CountryBlock', methods=['GET', 'POST'])  
def country_blocker_unblocker():
   global server
   result1 , result2 = str() , str()

   if request.method == 'GET':
      return render_template('CountryBlock.html')

   elif request.method == 'POST':
      countryToBlock = request.form.get('CountryToBlock').lstrip(' ')
      countryToUnblock = request.form.get('CountryToUnblock').lstrip(' ')
      if len(countryToBlock) > 0: #if the user has typed a country name
       result1 = server.activateCountryBlocker(countryToBlock)
      if len(countryToUnblock) > 0:
       result2 = server.activateCountryUnBlocker(countryToUnblock)

      #return template with feedback information whever or not the operation has succesed
      return render_template('CountryBlock.html'
      ,Country_name1=countryToBlock,Country_name2=countryToUnblock,Country_feedback1=result1,Country_feedback2=result2) 
   

@SentryApp.route('/start', methods=['GET', 'POST'])  
def start():
   global server
   interfaces = get_available_interfaces()
   if request.method == 'GET':
      return render_template('chooseInterface.html',interfaces=interfaces)
   elif request.method == 'POST':
      #getting information from the form
      interface = request.form.get('interface').lstrip(' ')
      email = "noNeedforemail@gmail.com"
      password = "noNeedForpassword123"
      results =  validate(interface, email) 
      
      if results[0]: #if the result is valid
         server = serverLogic(interface,email,password) #initialize the server modules
         return render_template('index.html') 
      else:
         #return the same form with error information
        return render_template('chooseInterface.html',interfaces=interfaces,interface_feedback=results[1],email_feedback=results[2]
        ,interface_value=interface  ,email_value=email )
@SentryApp.post('/start')  
def start_menu():
   global server
   interfaces = get_available_interfaces()
   #getting information from the form
   interface = request.form.get('interface').lstrip(' ')
   email = request.form.get('email').lstrip(' ')
   password = request.form.get('email_password').lstrip(' ')
   results =  validate(interface,email) 
   if results[0]: #if the result is valid
      server = serverLogic(interface,email,password) #initialize the server modules
      return render_template('index.html') 
   else:
      #return the same form with error information
      return render_template('start.html',interfaces=interfaces,interface_feedback=results[1],email_feedback=results[2]
      ,interface_value=interface  ,email_value=email )

@SentryApp.route('/home', methods=['GET', 'POST'])  
def midFrame():
   global Syn, Arp, Dns,Port, server
   dataToPass = server.get_data()
   #server.print_alerts()

   if request.method == 'POST':
       form_data = request.form

       if 'SynFloodDetector' in form_data and Syn == 'off':
        Syn ='on'
        server.activateSynFloodDetector()

       elif 'SynFloodDetector'not in form_data and Syn == 'on':
          Syn ='off'
          server.disableSynFloodDetector()

       if 'DnsSpoofDetector' in form_data and Dns == 'off':
          Dns = 'on'
          server.activateDnsSpoofDetector()

       elif 'DnsSpoofDetector' not in form_data and Dns == 'on':
           Dns = 'off'
           server.disableDnsSpoofDetector()

       if 'ArpSpoofDetector' in form_data and Arp == 'off':
             Arp = 'on'
             server.activateArpSpoofDetector()

       elif 'ArpSpoofDetector' not in form_data and Arp == 'on':
           Arp = 'off'
           server.disableArpSpoofDetector()

       if 'PortScanningDetector' in form_data and Port == 'off':
          Port = 'on'
          server.activatePortScanningDetector()

       elif 'PortScanningDetector' not in form_data and Port == 'on':
           Port = 'off'
           server.disablePortScanningDetector()

   return render_template('home.html',Syn=Syn,Dns=Dns,Arp=Arp,Port=Port)

@SentryApp.get('/bottomFrame')  
def bottom_frame():  
      return render_template('bottomFrame.html')



@SentryApp.get('/displaySql')  
def displayData():
   global server
   manager = server.get_manager()
   data_set = manager.get()
   scanId =  manager.get_data(data_set,"SCANID")
   scanDate =  manager.get_data(data_set ,"SCAN_DATE")
   typeOfAttack =  manager.get_data(data_set ,"TYPE_OF_ATTACK")
   routerHostName =  manager.get_data(data_set ,"ROUTER_HOST_NAME")
   attackerMac =  manager.get_data(data_set ,"ATTACKER_MAC_ADDRESS")
   attackerName =  manager.get_data(data_set ,"ATTACKER_NAME")
   return render_template('displaySql.html', scanId = scanId, scanDate = scanDate,
   typeOfAttack = typeOfAttack, routerHostName = routerHostName, attackerMac = attackerMac, attackerName = attackerName)    
              

def shutdownApp():
    func = request.environ.get('werkzeug.server.shutdown') # creates an object that shuts down the server
    if func is None: # if the object is None its not a Werkzeug Server or if we run it as a seperate thread
        raise RuntimeError('Not running with the Werkzeug Server')
    func() # activate kill
    
@SentryApp.get('/shutdown')
def shutdown():
    shutdownApp()
    return 'Server shutting down...'

def check_sudo():
   if geteuid() != 0:
      print("You need to have root privileges to run this script!")
      exit()
      
def main():
    global server
    try:
     SentryApp.run(host="127.0.0.1",port=5000)
     server.shutdown()
     print("exit successfuly from application")
    except Exception as e:
       print(e)


if __name__ == '__main__':
   check_sudo()
   main()
