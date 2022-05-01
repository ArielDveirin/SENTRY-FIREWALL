from subprocess import Popen ,PIPE



countries_dict = { 
"AFGHANISTAN" : "AF" ,

"CANADA" :  "CA",

"IRAN" : "IR" ,

"IRAQ": "IQ" ,

"IRELAND" : "IE" ,

"ISRAEL" : "IL" ,

"ITALY" : "IT",

"JAMAICA": "JM",

"JAPAN" : "JP",

"JORDAN" : "JO" ,

"NORWAY" : "NO" , 

"OMAN" : "OM" ,

"PAKISTAN" : "PK" ,

"PALAU" : "PW" ,

"PANAMA" :"PA" ,

"PAPUA NEW GUINEA" : "PG" ,

"PARAGUAY"  :"PY" ,

"PERU" : "PE" ,

"PHILIPPINES" : "PH" ,

"POLAND" : "PL" ,

"PORTUGAL" : "PT" , 

"QATAR" : "QA" , 

"ROMANIA" : "RO" , 

"RUSSIA" : "RU" ,

"RWANDA" : "RW" ,

"SAUDI ARABIA": "SA" ,

"SENEGAL" : "SN" , 

"SERBIA" : "RS" ,

"SEYCHELLES" : "SC" ,

"SINGAPORE" : "SG" , 

"SLOVAKIA" : "SK" ,

"SLOVENIA" : "SI" , 

"SOMALIA"  :"SO" , 

"SOUTH AFRICA" : "ZA" ,

"SPAIN" : "ES",

"SRI LANKA" : "LK",

"SUDAN" : "SD" ,

"SWEDEN" :  "SE" , 

"SWITZERLAND" : "CH" ,

"SYRIA" : "SY" ,

"TAIWAN" : "TW",

"TAJIKISTAN" : "TJ" ,

"TANZANIA" : "TZ" ,

"THAILAND": "TH" ,
"TOGO" :'TG' ,

"TONGA" : "TO" ,

"TUNISIA" :"TN",

"TURKEY" : "TR" ,

"TURKMENISTAN" : "TM" ,

"UGANDA" :"UG" ,

"UKRAINE": "UA" ,

"UNITED ARAB EMIRATES" :"AE" ,

"UNITED KINGDOM" :"GB" ,

"UNITED STATES" :"US" ,

"URUGUAY": "UY" ,

"UZBEKISTAN": "UZ" ,


"VENEZUELA" :"VE" ,

"VIETNAM": "VN" ,

"YEMEN" :"YE",

"ZAMBIA": "ZM",

"ZIMBABWE" :"ZW"
}


class Country_Blocker():
    def __init__(self):
        self.countries = list()
        self.path_to_blocker = "./Block_ips/Blocker.sh"
        self.path_to_unblocker = "./Block_ips/UnBlock.sh"

    def validate(self,country_name):
        if country_name.upper() not in countries_dict:
            return "This country is not in our database records, sorry :(" 
        if country_name in self.countries:
            return "This Country is already in the black list" 
        return None

    def block(self, country_name):
        country_name = country_name.lower()
        result = self.validate(country_name)
        if result is not None:
            return result
        command = [self.path_to_blocker ,countries_dict[country_name.upper()].lower() ,country_name.replace(" ","_")]
        return self.execute(command,country_name)

    def execute(self,cmd, country_name):
        try:
            proc = Popen(cmd,stderr = PIPE,)
            stderr = proc.communicate()[1]
            if stderr.decode() == "" or "ipdeny" in stderr.decode():
                self.countries.append(country_name)
                return "Opreation has been done successfuly"
            return stderr
        except Exception as e:
            return e

    def unblock(self ,country_name):
        country_name = country_name.lower()
        result = self.validate(country_name)
        if result != "":
            return result
        command = [self.path_to_unblocker ,country_name.replace(" ","_")]
        return self.execute(command,country_name)
            
        