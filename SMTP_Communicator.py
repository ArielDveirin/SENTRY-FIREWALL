"""IMPORTNAT!!! in order to send mails with our class you need to allow less scure apps to
send mails , follow the instructions in the next page to
enable that option: https://hotter.io/docs/email-accounts/secure-app-gmail/
"""


from smtplib import SMTP_SSL 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

SERVER_NAME = 'smtp.gmail.com'
PORT = 465


class SmtpCommunicator():
    def __init__(self, gmail_username, gmail_password):
        self.username = gmail_username
        self.password = gmail_password
    def build_msg(self,subject,to_address,log_file_name):
    # Create the container (outer) email message.
     msg = MIMEMultipart()
     msg['Subject'] = subject
     msg['From'] = self.gmail_username
     msg['To'] = to_address 
     with open(log_file_name, 'r') as fp:
        file = MIMEText(fp.read())
        msg.attach(file)

    

    def send(self,msg):
        # Create a SSLContext object with default settings.
     context = ssl.create_default_context() 
     try:
        with SMTP_SSL(SERVER_NAME, port=PORT, context=context) as conn:
            conn.set_debuglevel(False)
            conn.login(self.username, self.password)
            conn.sendmail(msg['From'], msg['To'], msg.as_string())
            print("success!")
            conn.quit()
     except Exception as e:
        print(e)

