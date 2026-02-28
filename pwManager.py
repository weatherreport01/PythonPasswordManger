import base64
import os
import tkinter as tk
from tkinter import filedialog as fd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# this video helped me a lot with using Fernet. Especially, encoding and decoding https://www.youtube.com/watch?v=O8596GPSJV4
class PasswordManager:
    
    def __init__(self):
        self.vaultKey = None
        self.vaultFile = None
        self.vaultDictionary = {}
    
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
        try:
            with open(path,'rb') as f:
                salt = f.read(16)
                readKey = f.read()
        except Exception as e:
            print(e)
        pw = attemptedPassword.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=1_200_000
        )
        resultKey = base64.urlsafe_b64encode(kdf.derive(pw))
        if readKey == resultKey:
            self.vaultKey = resultKey
            return True
        else:
            return False

    def createFile(self, path:str)-> None:
        self.vaultFile = path
        with open(self.vaultFile,'w'):
            pass

    def loadFile(self,path: str) -> None:
        self.vaultFile = path
        try:
            with open(path,'r') as f:
                for entry in f:
                    website, password = entry.strip().split(":") # we are using a dictionary so to seperate the website and password (key, value pairs), we use split
                    self.vaultDictionary[website] = Fernet(self.vaultKey).decrypt(password.encode()).decode()
        except Exception as e:
            print(e)
    def newEntry(self,website:str,password:str)-> None:
        self.vaultDictionary[website] = password

        if self.vaultFile is not None:
            with open(self.vaultFile,'a') as f:
                encryptedPw = Fernet(self.vaultKey).encrypt(password.encode())
                f.write(website + ":" + encryptedPw.decode() + "\n")

    def deleteEntry(self, website:str) -> None:
        if website in self.vaultDictionary:
            self.vaultDictionary.pop(website) 
    
    def saveToFile(self):
        if self.vaultFile is not None:
            try:
                with open(self.vaultFile, "w") as f:
                    for site, password in self.vaultDictionary.items():
                        encryptedPassword = Fernet(self.vaultKey).encrypt(password.encode())
                        f.write(site + ":" + encryptedPassword.decode() + "\n")
            except Exception as e:
                print(e)

    def getPassword(self,website:str) -> str:
        return self.vaultDictionary[website]
    
    def importPasswords(self, passwords:dict) -> None:
        for website, password in passwords.items():
            self.newEntry(website, password)

# -----------STUFF TO DO -----------
# need to make menu with logic and strict rules - tkinter gui?

class ProgramGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry("500x500")
        self.root.title("Python Password Vault")
        self.passwordManger = PasswordManager()

        self.vaultPath = None
        self.vaultKeyPath = None
        self.defaultTitleFont = ("Arial", 16, "Bold")

    def displayStartupMenu(self):
        self.clearGUI()

        label = tk.Label(self.root, text="Welcome! Choose an option below:", font=self.defaultTitleFont)
        label.pack(pady=15)

        tk.Button(self.root, text="Load Vault", width=20,command=self.loadVaultLocation).pack(pady=10)
        tk.Button(self.root, text="Create new vault", width=20, command=self.createVault).pack(pady=10)
        

    def loadVaultLocation(self):

        keyFile = fd.askopenfilename(title="Select your key file", filetypes=[("Key files", "*.key")])
        vaultFile = fd.askopenfilename(title="Select your vault file", filetypes=[("Text files", "*.txt")])
        self.vaultKeyPath = keyFile
        self.vaultPath = vaultFile

    def createVault(self):
        vaultFile = fd.askdirectory(title = "Select where you want to create your vault")
        
        self.vaultPath = vaultFile

        vaultKeyFile = fd.askdirectory(title="Where do you want to store your keyfile?")
        self.vaultKeyPath = vaultKeyFile
        

    def clearGUI(self):
        # used to clear all elements within the GUI. Used to prevent visual bugs navigating between menus
        for widget in self.root.winfo_children():
            widget.destroy()


    def showLoginMenu(self):
        self.clearGUI()
        label = tk.Label(self.root, text="Enter your master password:",font=self.defaultTitleFont)


    def displayMainMenu(self):

        # rewrite needed


        frame = tk.Frame(self.root)
        label = tk.Label(frame, text="Main Menu", font=self.defaultTitleFont)
        label.pack(pady=10)

        tk.Button(frame, text="Add Password", width=20, command=self.addPassword).pack(pady=5)
        tk.Button(frame, text="View Passwords", width=20, command=self.viewPassword).pack(pady=5)
        tk.Button(frame, text="Delete Password", width=20, command=self.deletePassword).pack(pady=5)
        tk.Button(frame, text="Exit", width=20, command = self.root.destroy()).pack(pady=5)
      
       
