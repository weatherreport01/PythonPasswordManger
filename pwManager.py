import base64
import os
import tkinter as tk
from tkinter import filedialog as fd
from tkinter import messagebox
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

    def deleteEntry(self, website:str) -> None:
        if website in self.vaultDictionary:
            self.vaultDictionary.pop(website) 

    
    def saveToFile(self) -> None:
        if self.vaultFile is not None:
            try:
                with open(self.vaultFile, "w") as f:
                    for site, password in self.vaultDictionary.items():
                        encryptedPassword = Fernet(self.vaultKey).encrypt(password.encode())
                        f.write(site + ":" + encryptedPassword.decode() + "\n")
            except Exception as e:
                print(e)
    def getPasswords(self) -> dict:
        return self.vaultDictionary
    
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
        self.passwordManager = PasswordManager()

        self.vaultPath = None
        self.vaultKeyPath = None
        self.defaultTitleFont = ("Arial", 16, "Bold") # annoying to keep typing this so decided to put it here
        self.root.protocol(("WM_DELETE_WINDOW"), self.exit)
        self.displayStartupMenu()

    def displayStartupMenu(self):
        # function called on initialization
        self.clearGUI()
        
        label = tk.Label(self.root, text="Welcome! Choose an option below:", font=self.defaultTitleFont)
        label.pack(pady=15)

        tk.Button(self.root, text="Load Vault", width=20,command=self.loadVault).pack(pady=10)
        tk.Button(self.root, text="Create new vault", width=20, command=self.createVault).pack(pady=10)
        

    def loadVault(self):
        # need to add a file cancel check
        keyFile = fd.askopenfilename(title="Select your key file", filetypes=[("Key files", "*.key")])
        if not keyFile:
            return
        vaultFile = fd.askopenfilename(title="Select your vault file", filetypes=[("Text files", "*.txt")])
        if not vaultFile:
            return
        self.vaultKeyPath = keyFile
        self.vaultPath = vaultFile
        self.displayLoginMenu()

    def createVault(self):
        # need to add a file cancel check
        vaultFile = fd.asksaveasfilename(title = "Select where you want to create your vault")
        if not vaultFile:
            return
        self.vaultPath = vaultFile

        vaultKeyFile = fd.asksaveasfilename(title="Where do you want to store your keyfile?")
        if not vaultKeyFile:
            return
        self.vaultKeyPath = vaultKeyFile


    def createNewMasterPassword(self):
        pass

    def clearGUI(self):
        # used to clear all elements within the GUI. Used to prevent visual bugs navigating between menus
        for widget in self.root.winfo_children():
            widget.destroy()


    def displayLoginMenu(self):
        self.clearGUI()
        label = tk.Label(self.root, text="Enter your master password",font=self.defaultTitleFont)
        label.pack(pady=5)
        pwEntry = tk.Entry(self.root, width=30)
        pwEntry.pack()

        feedbackLabel = tk.Label(self.root,text="", width=20)
        feedbackLabel.pack(pady=5)

        loginButton = tk.Button(self.root, text = "Login", command=tryLogin, width=20)
        loginButton.pack(pady=5)

        # looked up different ways to do this and decided to do it this way. Can't pass arguments with tk button.
        def tryLogin():
            attemptPassword = pwEntry.get()

            if not attemptPassword:
                feedbackLabel.config(text="Can't be empty!")
            
            if self.passwordManager.loadKey(self.vaultKeyPath, attemptPassword):
                self.passwordManager.loadFile(self.vaultPath)
                self.displayMainMenu()
            else:
                feedbackLabel.config(text="Wrong password! Try again.")

    def displayMainMenu(self):

        # rewrite needed
        self.clearGUI()
        label = tk.Label(self.root, text="Main Menu", font=self.defaultTitleFont)
        label.pack(pady=10)

        addPwButton = tk.Button(self.root, text="Add Password", width=20, command=self.addPassword)
        addPwButton.pack(pady=5)
        viewPwButton = tk.Button(self.root, text="View Passwords", width=20, command=self.viewPasswords)
        viewPwButton.pack(pady=5)
        deletePwButton = tk.Button(self.root, text="Delete Password", width=20, command=self.deletePassword)
        deletePwButton.pack(pady=5)
        exitButton = tk.Button(self.root, text="Exit", width=20, command = self.exit)
        exitButton.pack(pady=5)

    
    def exit(self):
        if messagebox.askyesno(title="Are you sure you want to exit? (Changes will be saved on exit)"):
            self.passwordManager.saveToFile()
            self.root.destroy()
      
    def addPassword(self):
        self.clearGUI()
        topFrame = tk.Frame(self.root)
        topFrame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        backButton = tk.Button(topFrame,text="Back to main menu", command=self.displayMainMenu, width=10)
        backButton.pack(side=tk.LEFT)

        websiteLabel = tk.Label(self.root, text="Enter a website: ")
        websiteLabel.pack(pady=5)
        websiteEntry = tk.Entry(self.root, width=30)
        websiteEntry.pack()

        passwordLabel = tk.Label(self.root, text="Enter the password")
        passwordLabel.pack(pady=5)
        passwordEntry = tk.Entry(self.root, width=30)
        passwordEntry.pack()

        feedbackLabel = tk.Label(self.root,text="",width=20)
        feedbackLabel.pack(pady=5)
        submitButton = tk.Button(self.root, text="Add to vault", command=addToVault, width=20)
        submitButton.pack(pady=5)

        def addToVault():
            if not websiteEntry.get().strip() or not passwordEntry.get().strip():
                feedbackLabel.config(text="Invalid Entry! Website or password is empty!")
            else:
                self.passwordManager.newEntry(websiteEntry.get().strip(),passwordEntry.get().strip())
                feedbackLabel.config(text="Added password successfully!")

    def viewPasswords(self):
        self.clearGUI()

        topFrame = tk.Frame(self.root)
        topFrame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        backButton = tk.Button(topFrame,text="Back to main menu", command=self.displayMainMenu, width=10)
        backButton.pack(side=tk.LEFT)

        contents = ""
        for website, password in self.passwordManager.getPasswords().items():
            contents += f"{website}: {password}\n"

        displayLabel = tk.Label(self.root,text=contents, width=50)
        displayLabel.pack()
    
    def deletePassword(self):
        self.clearGUI()
        topFrame = tk.Frame(self.root)
        topFrame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        backButton = tk.Button(topFrame,text="Back to main menu", command=self.displayMainMenu, width=10)
        backButton.pack(side=tk.LEFT)

        websiteLabel = tk.Label(self.root, text="Enter the website")
        websiteLabel.pack(pady=5)
        websiteEntry = tk.Entry(self.root, width=30)
        websiteEntry.pack()

        feedbackLabel = tk.Label(self.root,text="",width=20)
        feedbackLabel.pack(pady=5)
        submitButton = tk.Button(self.root, text="Delete from vault",command=deleteFromVault, width=20)
        submitButton.pack(pady=5)

        def deleteFromVault():
            if not websiteEntry.get().strip():
                feedbackLabel.config(text="Entry can't be empty!")
            elif websiteEntry.get().strip() not in self.passwordManager.getPasswords().keys():
                feedbackLabel.config(text="Not in the vault!")
            else:
                self.passwordManager.deleteEntry(websiteEntry.get().strip())

