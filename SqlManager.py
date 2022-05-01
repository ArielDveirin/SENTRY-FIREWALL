import sqlite3
from cryptography.fernet import Fernet
from os import path


class Cryptography():

  def generate_key(self):
     key = Fernet.generate_key()
     with open("universal.key","wb") as key_files:
        key_files.write(key)
     return key

  def encrypt(self, data , key):

     encodeSecret = data.encode()
     fer  = Fernet(key)
     return fer.encrypt(encodeSecret)


  def decrypt(self, encryptedData,key):
      fer  = Fernet(key)
      decryptSecret = fer.decrypt(encryptedData)
      return decryptSecret.decode()

  def load_Key(self):
     key = open("universal.key","rb").read()
     return key


class SQL_Manager():
    def __init__(self):
        self.cryptography = Cryptography()
        self.key = None
        self.database_name = 'database.sqlite'
        self.exsits = path.isfile(self.database_name)
        self.conn = sqlite3.connect(self.database_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        if not self.exsits:
            self.key = self.cryptography.generate_key()
            self.Create_database()
        else:
            self.key = self.cryptography.load_Key()

    def __del__(self):
        self.cursor.close()
        self.conn.close()


    def Create_database(self):
        self.cursor.execute('''CREATE TABLE SCANS(
         SCANID INTEGER PRIMARY KEY AUTOINCREMENT,
         SCAN_DATE          DATETIME    NOT NULL,
         TYPE_OF_ATTACK         VARCHAR(25)    NOT NULL,
         ROUTER_HOST_NAME         VARCHAR(30)  NOT NULL,
         ATTACKER_MAC_ADDRESS VARCHAR(20) NOT NULL,
         ATTACKER_NAME        VARCHAR(20)    NOT NULL);''')
        self.conn.commit()
        print("Tbale SCANS created successfully")


    def add(self, date , attack_name, network_name, mac_address, attacker_name):
      try:
        coloums = [date,attack_name,network_name,mac_address,attacker_name]
        encrypted_colums =[]
        for data in coloums:
            encrypted_colums.append(self.cryptography.encrypt(data,self.key))
        query = "INSERT INTO SCANS(SCAN_DATE,TYPE_OF_ATTACK,ROUTER_HOST_NAME,ATTACKER_MAC_ADDRESS,ATTACKER_NAME) VALUES (? ,? ,? , ?, ?);"
        self.cursor.execute(query ,tuple(encrypted_colums))
        self.conn.commit()
        print("Records created successfully")
      except Exception as e:
          print(e)


    def get(self):
     list_of_rows = []
     query = f"SELECT * FROM SCANS;"
     try:
        self.cursor.execute(query)
        results = self.cursor.fetchall() 
        fields = [ix[0] for ix in self.cursor.description]

        for row in results:
            db_dict = {}
            db_dict[fields[0]] = row[0]

            for i in range(1,len(row)- 1):
                   value = self.cryptography.decrypt(row[i],self.key)
                   db_dict[fields[i]] = value

            list_of_rows.append(db_dict)

     except Exception as e:
         print(e)
         
     return list_of_rows
    def get_data(self,data_set,requested_coulom):
        list_of_data = list()
        for row in data_set:
            list_of_data.append(row.get(requested_coulom))

        return list_of_data
            