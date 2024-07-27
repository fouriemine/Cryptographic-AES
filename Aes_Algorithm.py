import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from cryptography.fernet import Fernet
import hashlib
import os
import base64


class Aes_Algorithm:
    def __init__(self, master):
        self.key_path_var = tk.StringVar()
        self.master = master
        self.key = None
        self.SALT_SIZE = 16
        self.ITERATIONS = 100000

    #method to create the GUI
    def create_gui(self):
        self.master.title("Cryptography - Group 46") #set the title of the form displayed
        self.master.configure(background='white') #set the background color of the main form
        # Create UI elements

        #create the tab control
        tab_control = ttk.Notebook(root)

        #create first tab for encryption
        tabEnc = ttk.Frame(tab_control)
        tab_control.add(tabEnc, text='Encrypt a file')

        #create a second tab for decryption
        tabDec = ttk.Frame(tab_control)
        tab_control.add(tabDec,text='Decrypt a file')

        #create style for the background of the tab control
        style = ttk.Style()
        style.configure('TNotebook', background='white')

        #add all widgets to encrypt tab

        #display heading that is on top of the page
        self.lblheading = tk.Label(self.master, text="Cryptography - Group 46", foreground='pink', background='white', font=("Helvetica", 16, "bold"))
        self.lblheading.pack(pady=15)

        #create a frame to add the 'select file' part
        self.file_frameE = tk.Frame(tabEnc)
        self.file_frameE.pack(pady=15)

        #create a select label to display to the user
        self.lblselectE = tk.Label(self.file_frameE, text="Select File:")
        self.lblselectE.pack(side=tk.LEFT)

        #create variable to store file path
        self.file_path_varE = tk.StringVar()
        self.file_path_entryE = tk.Entry(self.file_frameE, textvariable=self.file_path_varE, width=30)
        self.file_path_entryE.pack(side=tk.LEFT)

        #button that calls the browse file method
        self.btnbrowseE = tk.Button(self.file_frameE, text="Browse", command=self.browse_fileE)
        self.btnbrowseE.pack(side=tk.LEFT)

        #create a frame to add the 'select password' part
        self.password_frame = tk.Frame(tabEnc)
        self.password_frame.pack(pady=15)

        #display label to show the password must be inputted
        self.lblpassword = tk.Label(self.password_frame, text="Password:")
        self.lblpassword.pack(side=tk.LEFT)

        #allow user to enter the password
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(self.password_frame, textvariable=self.password_var, width=30, show="*")
        self.password_entry.pack(side=tk.LEFT)

        #button to toggle between password visibility
        self.show_password_button = tk.Button(self.password_frame, text="Show", command=self.toggle_password_visibility)
        self.show_password_button.pack(side=tk.LEFT)

        #button to encrypt
        self.btn_encrypt = tk.Button(tabEnc, text="Encrypt", command=self.encrypt_file)
        self.btn_encrypt.pack(pady=15)

        #add all components to decrypt tab

        #create frame for decrypt file that will be selected
        self.file_frameD = tk.Frame(tabDec)
        self.file_frameD.pack(pady=15)

        #lbl to show that a file must be selected to decrypt
        self.lblselectD = tk.Label(self.file_frameD, text="Select File:")
        self.lblselectD.pack(side=tk.LEFT)

        #allows for file path to be entered
        self.file_path_varD = tk.StringVar()
        self.file_path_entryD = tk.Entry(self.file_frameD, textvariable=self.file_path_varD, width=30)
        self.file_path_entryD.pack(side=tk.LEFT)

        # button that calls the browse file method
        self.btnbrowseD = tk.Button(self.file_frameD, text="Browse", command=self.browse_fileD)
        self.btnbrowseD.pack(side=tk.LEFT)

        #create key frame
        self.key_frame = tk.Frame(tabDec)
        self.key_frame.pack(pady=15)

        #label to show that a key file must be selected
        self.lblkey = tk.Label(self.key_frame, text="Key File:")
        self.lblkey.pack(side=tk.LEFT)

        #allows key file path to be entered
        self.key_path_entry = tk.Entry(self.key_frame, textvariable=self.key_path_var, width=30)
        self.key_path_entry.pack(side=tk.LEFT)

        #button to browse for the key file
        self.btnbrowse_key = tk.Button(self.key_frame, text="Browse", command=self.browse_key_file)
        self.btnbrowse_key.pack(side=tk.LEFT)


        #button to decrypt the file - calls the decrypt method
        self.btn_decrypt = tk.Button(tabDec, text="Decrypt", command=self.decrypt_file)
        self.btn_decrypt.pack(pady=15)

        #add tab control to the gui
        tab_control.pack(expand=1,fill='both')

    #browse for file that is decrypted to encrypt
    def browse_fileE(self):
        try:
            file_path = filedialog.askopenfilename() #get file path
            self.file_path_varE.set(file_path) #set file path
        except Exception as e: #catch any exceptions when browsing for a file to encrypt
            messagebox.showerror("Error", f"Failed to browse file: {str(e)}")

    #browse for file that is encrypted to decrypt
    def browse_fileD(self):
        try:
            file_path = filedialog.askopenfilename() #get file path
            self.file_path_varD.set(file_path) #set file path
        except Exception as e: #catch any exceptions when browsing for a file to decrypt
            messagebox.showerror("Error", f"Failed to browse file: {str(e)}")

    #method to browse for the key file(derived from the password) used to decrypt an encrypted file
    def browse_key_file(self):
        try:
            key_path = filedialog.askopenfilename() #get file path
            self.key_path_var.set(key_path) #set file path
        except Exception as e: #catch any exceptions when browsing for a key file to use while decrypting
            messagebox.showerror("Error", f"Failed to browse key file: {str(e)}")

    #method to toggle between if the password is visible or not
    def toggle_password_visibility(self):
        current_show_state = self.password_entry.cget("show")
        new_show_state = "" if current_show_state else "*"
        self.password_entry.config(show=new_show_state) #change the textbox's show state according to if user clicks on the show button

    #method called to encrypt the file
    def encrypt_file(self):
        file_path = self.file_path_varE.get() #get the file path
        password = self.password_var.get() #get the password

        if file_path and password: #if both are entered continue
            try:
                with open(file_path, "rb") as file:
                    data = file.read() #read the data from the file
                self.key = self.derive_key_from_password(password) #call the method to generate the key
                fernet = Fernet(self.key)
                encrypted_data = fernet.encrypt(data) #encrypt the data

                encrypted_file_path = file_path + ".enc" #create the new encrypted file path
                with open(encrypted_file_path, "wb") as file:
                    file.write(encrypted_data) #read new encrypted data to that file

                key_file_path = file_path + ".key" #create new key file path
                with open(key_file_path, "wb") as key_file:
                    key_file.write(self.key) #write key created to that file path

                messagebox.showinfo("Success", "File encrypted successfully.")
                self.clear_textboxes()
                
                os.remove(file_path) #remove original file
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to encrypt file: {str(e)}")
        else:
            messagebox.showerror("Error", "Ensure file is chosen and password is inserted")

    #method called to decrypt the file
    def decrypt_file(self):
        file_path = self.file_path_varD.get() #get the file path
        key_path = self.key_path_var.get() #get the password

        if file_path  and key_path: #if both are entered continue
            try:
                with open(key_path, "rb") as key_file:
                    self.key = key_file.read() #read the data from the key file

                fernet = Fernet(self.key)

                with open(file_path, "rb") as file:
                    data = file.read() #read the data from the file

                decrypted_data = fernet.decrypt(data) #decrypt the data

                decrypted_file_path = file_path.replace(".enc", "")
                with open(decrypted_file_path, "wb") as file:
                    file.write(decrypted_data) #write the decrypted data to the file

                messagebox.showinfo("Success", "File decrypted successfully.")
                self.clear_textboxes() #reset the form
                os.remove(file_path) #remove encrypted file that was stored
                os.remove(key_path) #remove key file that was stored
                
            except FileNotFoundError:
                messagebox.showerror("Error", "Key file not found. Make sure the file was encrypted with the current version of the application.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")
        else:
            messagebox.showerror("Error", "Ensure file and key file are selected.")

    #salt method that uses random values to enhance password to key derivation to ensure stronger encryption
    def derive_key_from_password(self, password):
        salt = os.urandom(self.SALT_SIZE) #gets random salt
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, self.ITERATIONS) #uses salt to create a key
        fernet_key = base64.urlsafe_b64encode(key) #usees key to create a fernet key
        return fernet_key #returns the fernet key  used to encryptthe data

    #reset all the texboxes to empty
    def clear_textboxes(self):
            self.file_path_varE.set("")
            self.file_path_varD.set("")
            self.password_var.set("")
            self.key_path_var.set("")

#run the application and gui
if __name__ == "__main__":
    root = tk.Tk()
    app = Aes_Algorithm(root)
    app.create_gui()
    root.mainloop()

