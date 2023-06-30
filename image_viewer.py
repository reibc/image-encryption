from genericpath import isfile
from multiprocessing.sharedctypes import Value
from tkinter import Listbox
import PySimpleGUI as sg
import os.path
import hashlib
import enc_script
from PIL import Image

from h11 import CLOSED
from Crypto.Cipher import AES

def enc_image(input_data,key,iv,filepath):
	cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
	enc_data = cfb_cipher.encrypt(input_data)

	enc_file = open(filepath+"/encrypted.enc", "wb")
	enc_file.write(enc_data)
	enc_file.close()

	
def dec_image(input_data,key,iv,filepath):
	cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
	plain_data = cfb_decipher.decrypt(input_data)

	output_file = open(filepath+"/output.png", "wb")
	output_file.write(plain_data)
	output_file.close()

file_list_column = [
    [
        sg.Text("Image Folder"),
        sg.In(size=(25,1), enable_events=True, key="-FOLDER-"),
        sg.FolderBrowse(),
    ],
    [
        sg.Listbox(
            values=[], enable_events=True, size=(40,20),
            key="-FILE LIST-"
        )
    ],
    
    [
        sg.Text("KEY"),
        sg.In(size=(25,1), enable_events=True, key="-ENCRYPT KEY-", password_char='*')

    ],
    [
        sg.Button(("Encrypt"), enable_events=True,
            key="-BUTTON ENCRYPT-"
        ),
        sg.Button(("Decrypt"), enable_events=True,
            key="-BUTTON DECRYPT-"
        )
    ],
]

image_viewer_column = [
    [sg.Text("Choose an image from the list on the left:")],
    [sg.Text(size=(40,1), key="-TOUT-")],
    [sg.Image(key="-IMAGE-")]
]

layout = [
    [
        sg.Column(file_list_column),
        sg.VSeparator(),
        sg.Column(image_viewer_column)
    ]
]
window = sg.Window("Image Viewer", layout)

while True:
    event, values = window.read()
    if event == "Exit" or event == sg.WIN_CLOSED:
        break

    if event == "-FOLDER-":
        folder = values["-FOLDER-"]
        try:
            file_list = os.listdir(folder)
        except:
            file_list = []
        
        fnames = [
            f
            for f in file_list
            if os.path.isfile(os.path.join(folder, f))
            and f.lower().endswith((".png", ".gif"))
        ]
        window["-FILE LIST-"].update(fnames)
    elif event == "-FILE LIST-":
        try:
            filename = os.path.join(
                values["-FOLDER-"], values["-FILE LIST-"][0]
            )
            window["-TOUT-"].update(filename)
            try:
                im = Image.open(filename)
                window["-IMAGE-"].update(filename=filename)
                im.close()
            except:
                window["-IMAGE-"].update()
        except:
            pass

    elif event == "-BUTTON ENCRYPT-":
        try:
            filename = os.path.join(
               values["-FOLDER-"], values["-FILE LIST-"][0]
            )
        except:
            pass
        try:
            encryption_key = values["-ENCRYPT KEY-"]
            print("Encryption key is: ", encryption_key)
            if encryption_key:
                hash=hashlib.sha256(encryption_key.encode()) 
                p = hash.digest()
                key = p
                iv = p.ljust(16)[:16]
                print("Encoding key is: ",key)
                input_file = open(filename,'rb')
                input_data = input_file.read()
                input_file.close()
                enc_script.enc_image(input_data,key, iv, filename)
                sg.popup("ENCRYPTED")
                window["-IMAGE-"].update()
            else:
                sg.popup("Enter a valid key!")
        except:
            pass


    elif event == "-BUTTON DECRYPT-":
        try:
            filename = os.path.join(
               values["-FOLDER-"], values["-FILE LIST-"][0]
            )
        except:
            pass
        try:
            encryption_key = values["-ENCRYPT KEY-"]
            if encryption_key:
                hash=hashlib.sha256(encryption_key.encode()) 
                p = hash.digest()
                key = p
                iv = p.ljust(16)[:16]

                input_file = open(filename, "rb")
                input_data = input_file.read()
                input_file.close()
                enc_script.dec_image(input_data,key, iv,filename)
                sg.popup("Decrypted!!")
                window["-IMAGE-"].update(filename)
            else:
                sg.popup("Enter a valid key!")
        except:
            pass


window.close()