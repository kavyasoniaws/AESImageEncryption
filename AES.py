from tkinter import *
from tkinter import filedialog
#from PIL import Image,ImageTK
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_image():
    file = filedialog.askopenfilename()
    if file:
        with open(file, 'rb') as f:
            data = f.read()
        key = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = cipher.iv
        enc_file = os.path.join(os.path.dirname(file), 'encrypted.jpeg')
        with open(enc_file, 'wb') as f:
            f.write(iv + ct_bytes)
        key_entry.delete(0, END)
        key_entry.insert(0, key.hex())

def decrypt_image():
    file = filedialog.askopenfilename()
    if file:
        with open(file, 'rb') as f:
            data = f.read()
        iv = data[:16]
        ct = data[16:]
        key = bytes.fromhex(key_entry.get())
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        dec_file = os.path.join(os.path.dirname(file), 'decrypted.jpeg')
        with open(dec_file, 'wb') as f:
            f.write(pt)

root = Tk()
root.title("Image Encryption Using AES Algorithm")
root.geometry("300x300")
#image_0=Image.open('/Users/prachi/Desktop/AESImageEncryption/locker.jpeg')
#bck_end=ImageTK.PhotoImage(image_0)
#lbl=Label(root,image=bck_end)
#lbl.place(x=0,y=0)
root.configure(bg="light cyan")

key_label = Label(root, text="Key:")
key_label.place(x=350,y=200)
key_label.pack()

key_entry = Entry(root, show="*")
key_entry.place(x=200,y=200)
key_entry.pack()

encrypt_button = Button(root, text="Encrypt Image", command=encrypt_image)
encrypt_button.place(x=200,y=300)
encrypt_button.pack()

decrypt_button = Button(root, text="Decrypt Image", command=decrypt_image)
decrypt_button.pack()

root.mainloop()