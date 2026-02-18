import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# this video helped me a lot with using Fernet. Especially, encoding and decoding https://www.youtube.com/watch?v=O8596GPSJV4
class PasswordManager:
    
    def __init__(self):
        self.vaultKey = None
        self.vaultFile = None
        self.vaultDictionary = None
    
    def createKey(self, path:str, masterPassword:str) -> None:
        # https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet 
        # Code in this section was from this website above
        pw = masterPassword.encode('utf-8')
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=1_200_000
        )
        self.vaultKey = base64.urlsafe_b64encode(kdf.derive(pw))
        with open(path, 'wb') as f:
            f.write(salt + self.vaultKey)


    def loadKey(self, path:str, attemptedPassword:str) -> bool:
        with open(path,'rb') as f:
            salt = f.read(16)
            readKey = f.read()
        
        pw = attemptedPassword.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=1_200_000
        )
        resultKey = base64.urlsafe_b64encode(kdf.derive(pw))
        if readKey == resultKey:
            self.vaultFile == resultKey
            return True
        else:
            return False

    def createFile(self, path:str)-> None:
        self.vaultFile = path
        with open(self.vaultFile,'w'):
            pass

    def loadFile(self,path: str) -> None:
        self.vaultFile = path

        with open(path,'r') as f:
            for entry in f:
                website, password = entry.split(":") # we are using a dictionary so to seperate the website and password (key, value pairs), we use split
                self.vaultDictionary[website] = Fernet(self.vaultKey).decrypt(password.encode()).decode()

    def newEntry(self,website:str,password:str)-> None:
        self.vaultDictionary[website] = password

        if self.vaultFile is not None:
            with open(self.vaultFile,'a') as f:
                encryptedPw = Fernet(self.vaultKey).encrypt(password.encode())
                f.write(website + ":" + encryptedPw.decode() + "\n")

    def deleteEntry(self, website:str) -> None:
        if website in self.vaultDictionary:
            self.vaultDictionary.pop(website) 

    def getPassword(self,website:str) -> str:
        return self.vaultDictionary[website]
    
    def importPasswords(self, passwords:dict) -> None:
        for website, password in passwords.items():
            self.newEntry(website, password)

# -----------STUFF TO DO -----------
# using os import, I want it to create some folders and do some checks
# need to make menu with logic and strict rules - tkinter gui?