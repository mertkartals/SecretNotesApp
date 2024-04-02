from tkinter import *
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title = title_entry.get()
    message = user_text.get("1.0", END)
    master_secret = master_secret_input.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:  # Eğer başlık ya da mesaj ya da şifre girilmemişse
        messagebox.showinfo(title = "Hatalı işlem!", message= "Lütfen, tüm bilgileri girdiğinizden emin olun.")

    else:
        message_encrypted = encode(master_secret, message)
        try:                                                #Bir kod bloğunu hatalara karşı denetler.
            with open("mysecret.txt","a") as secret_file:
                secret_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:                           #Kod bloğunda bir hata durumunda işlemler yapmayı sağlar.
            with open("mysecret.txt","w") as secret_file:
                secret_file.write(f"\n{title}\n{message_encrypted}")
        finally:                                             #Eninde sonunda bunu yap demektir.
            title_entry.delete(0, END)
            user_text.delete("1.0", END)
            master_secret_input.delete(0, END)       #Ne kadarını sileceğini de belirledik.

def decrypt_file():
    message_encrypted = user_text.get("1.0",END)
    master_secret = master_secret_input.get()
    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Şifre çözülemedi!", message="Lütfen, tüm bilgileri girdiğinizden emin olun.")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            user_text.delete("1.0",END)
            user_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Hatalı işlem!", message="Lütfen, şifrelenmiş bilgileri girdiğinizden emin olun.")


#User Interface (kullanıcı arayüzü)
FONT = ("Times",13,"normal")
window = Tk()
window.title("Secret Notes")
window.config(padx=50, pady=30, bg="aliceblue")

big_title_label = Label(text="Secret Notes")
big_title_label.config(bg="aliceblue", font=("Times", 40, "bold"))
big_title_label.pack()

f = Frame(bg="aliceblue", height=15)
f.pack()

photo = PhotoImage(file="topsecret.png")
photo_label = Label(image=photo)
photo_label.pack()

f0 = Frame(bg="aliceblue", height=15)          #boşluk oluşturuyoruz.
f0.pack()

title_label = Label(text="Enter your title")
title_label.config(bg="aliceblue",font=FONT)
title_label.pack()

title_entry = Entry(width=30)
title_entry.pack()

user_text_label = Label(text="Enter your secret")
user_text_label.config(bg="aliceblue",font=FONT)
user_text_label.pack()

user_text = Text(width=30, height=15,font=FONT)
user_text.pack()

master_secret_label = Label(text="Enter master key",font=FONT)
master_secret_label.config(bg="aliceblue")
master_secret_label.pack()

master_secret_input = Entry(width=20)
master_secret_input.pack()

f1 = Frame(bg="aliceblue", height=10)
f1.pack()

save_button = Button(width=22, text="Save & Encrypt", font=FONT, command=save_and_encrypt)
save_button.config(bg="navy", fg="white")
save_button.pack()

f2 = Frame(bg="aliceblue", height=15)
f2.pack()

decrypt_button = Button(width=15, text="Decrypt", command=decrypt_file)
decrypt_button.config(bg="indigo", fg="white", font=FONT)
decrypt_button.pack()


window.mainloop()