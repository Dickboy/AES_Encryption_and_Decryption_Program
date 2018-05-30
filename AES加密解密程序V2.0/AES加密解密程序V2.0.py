# -*- coding: utf-8 -*-
"""
Created on Wed Apr  4 13:54:18 2018

@author: Sherlock Holmes
"""

from tkinter import *
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
import hashlib
from Crypto.Cipher import AES

seed = '1234567890123456'

# 口令hash返回16字节str
def hash_16B(password):
    md5 = hashlib.md5()
    md5.update(password)
    return md5.hexdigest()

# ECB模式初始化AES
def init_ECB(password):
    return AES.new(hash_16B(password), AES.MODE_ECB)

# CBC模式初始化AES
def init_CBC(password):
    return AES.new(hash_16B(password), AES.MODE_CBC, seed)

# CFB模式初始化AES
def init_CFB(password):
    return AES.new(hash_16B(password), AES.MODE_CFB, seed)

# OFB模式初始化AES
def init_OFB(password):
    return AES.new(hash_16B(password), AES.MODE_OFB, seed)

# 模式字典
modeDict = {
        'ECB': init_ECB,
        'CBC': init_CBC,
        'CFB': init_CFB,
        'OFB': init_OFB
        }

# AES加密
def encrypt_AES(text, password, mode):
    # 填充分组，使用PKCS7Padding填充方式, 确保其长度为16的整数倍
    # CFB模式不需要填充
    if mode != 'CFB':
        for i in range(0, (16 - text.__len__() % 16) % 16):
            text += b'\0'
    AESCipher = modeDict[mode](password)
    return AESCipher.encrypt(text)

# AES解密
def decrypt_AES(cipher, password, mode):
    AESCipher = modeDict[mode](password)
    return AESCipher.decrypt(cipher)

# 通过文件输入明文和口令，将结果输出到一个文件
def encrypt_AES_file(textPath, passwordPath, cipherPath, Emode):
    try:
        textFile = open(textPath, mode = 'rb')
    except IOError:
        # 明文文件路径错误
        return 1
    try:
        passwordFile = open(passwordPath, mode = 'rb')
    except IOError:
        # 口令文件路径错误
        return 2
    try:
        cipherFile = open(cipherPath, mode = 'wb')
    except IOError:
        # 密文文件路径错误
        return 3
    cipherFile.write( encrypt_AES(textFile.read(), passwordFile.read(), Emode) )
    textFile.close()
    passwordFile.close()
    cipherFile.close()
    return 0

# 通过文件输入密文和口令，将恢复的明文输出到一个文件
def decrypt_AES_file(cipherPath, passwordPath, textPath, Dmode):
    try:
        cipherFile = open(cipherPath, mode = 'rb')
    except IOError:
        # 密文文件路径错误
        return 1
    try:
        passwordFile = open(passwordPath, mode = 'rb')
    except IOError:
        # 口令文件路径错误
        return 2
    try:
        textFile = open(textPath, mode = 'wb')
    except IOError:
        # 明文文件路径错误
        return 3    
    textFile.write( decrypt_AES(cipherFile.read(), passwordFile.read(), Dmode) )
    cipherFile.close()
    passwordFile.close()
    textFile.close()
    return 0

# 调用格式示例
'''
encrypt_AES_file("C:\\Users\\Sherlock Holmes\\Desktop\\text.txt",
                 "C:\\Users\\Sherlock Holmes\\Desktop\\password.txt",
                 "C:\\Users\\Sherlock Holmes\\Desktop\\cipher.txt",
                 'OFB')# 加密
decrypt_AES_file("C:\\Users\\Sherlock Holmes\\Desktop\\cipher.txt",
                 "C:\\Users\\Sherlock Holmes\\Desktop\\password.txt",
                 "C:\\Users\\Sherlock Holmes\\Desktop\\plain.txt",
                 'OFB')# 解密
'''

tmp = Tk()
img1 = PhotoImage(file='encrypt.png')
img2 = PhotoImage(file='decrypt.png')

class GraphInterface(Frame):
    # 构造函数
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()
        
    # 窗体函数
    def createWidgets(self):
        # self.root = tk.Tk()
    
        self.nb = ttk.Notebook()
        
        self.master.title('AES加密解密程序')
        self.master.geometry('800x400')
        self.master.iconbitmap('aes.ico')
        
        self.filename1 = ""
        self.filename2 = ""
        
        # adding Frames as pages for the ttk.Notebook 
        # first page, which would get widgets gridded into it
        
        self.page1 = ttk.Frame(self.nb)
        self.image1 = Label(self.page1, image=img1)
        self.image1.pack(side=LEFT, fill=Y, padx=10, pady=10)
        self.label1 = Label(self.page1, text="请选择要加密的文本")
        self.label1.pack(side=TOP, fill=BOTH, padx=5, pady=5)
        self.label2 = Label(self.page1, text="明文文本路径：")
        self.label2.pack(padx=5, pady=5)
        self.txt1 = Text(self.page1, height=1, width=50)
        self.txt1.pack(padx=5, pady=5)
        self.fileChooser1 = Button(self.page1, text='选择文件', command=self.selectPlainText)
        self.fileChooser1.pack(padx=5, pady=5)
        self.label3 = Label(self.page1, text="密钥文本路径：")
        self.label3.pack(padx=5, pady=5)
        self.txt2 = Text(self.page1, height=1, width=50)
        self.txt2.pack(padx=5, pady=5)
        self.fileChooser2 = Button(self.page1, text='选择文件', command=self.selectPassword1)
        self.fileChooser2.pack(padx=5, pady=5)
        self.label4 = Label(self.page1, text="请选择加密方式：")
        self.label4.pack(padx=5, pady=5)
        self.comboList1 = ['ECB模式','CBC模式','CFB模式','OFB模式']
        self.combobox1 = ttk.Combobox(self.page1, values=self.comboList1)
        self.combobox1.pack(padx=5, pady=5)
        self.alertButton1 = Button(self.page1, text='开始', command=self.encrypt)
        self.alertButton1.pack(side=BOTTOM, padx=5, pady=10)
        
        # second page
        self.page2 = ttk.Frame(self.nb)
        self.image2 = Label(self.page2, image=img2)
        self.image2.pack(side=LEFT, fill=Y, padx=10, pady=10)
        self.label5 = Label(self.page2, text="请选择要解密的文本")
        self.label5.pack(side=TOP, fill=BOTH, padx=5, pady=5)
        self.label6 = Label(self.page2, text="密文文本路径：")
        self.label6.pack(padx=5, pady=5)
        self.txt3 = Text(self.page2, height=1, width=60)
        self.txt3.pack(padx=5, pady=5)
        self.fileChooser3 = Button(self.page2, text='选择文件', command=self.selectCipherText)
        self.fileChooser3.pack(padx=5, pady=5)
        self.label7 = Label(self.page2, text="密钥文本路径：")
        self.label7.pack(padx=5, pady=5)
        self.txt4 = Text(self.page2, height=1, width=60)
        self.txt4.pack(padx=5, pady=5)
        self.fileChooser4 = Button(self.page2, text='选择文件', command=self.selectPassword2)
        self.fileChooser4.pack(padx=5, pady=5)
        self.label8 = Label(self.page2, text="请选择解密方式：")
        self.label8.pack(padx=5, pady=5)
        self.comboList2 = ['ECB模式','CBC模式','CFB模式','OFB模式']
        self.combobox2 = ttk.Combobox(self.page2, values=self.comboList2)
        self.combobox2.pack(padx=5, pady=5)
        self.alertButton2 = Button(self.page2, text='开始', command=self.decrypt)
        self.alertButton2.pack(side=BOTTOM, padx=5, pady=10)
    
        self.nb.add(self.page1, text='加密')
        self.nb.add(self.page2, text='解密')
    
        self.nb.pack(expand=1, fill="both")
    
    def selectPlainText(self):
        self.filename1 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt1.delete(1.0, END)
        self.txt1.insert(1.0, self.filename1)
        
    def selectPassword1(self):
        self.filename2 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt2.delete(1.0, END)
        self.txt2.insert(1.0, self.filename2)
        
    def selectCipherText(self):
        self.filename3 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt3.delete(1.0, END)
        self.txt3.insert(1.0, self.filename3)
        
    def selectPassword2(self):
        self.filename4 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt4.delete(1.0, END)
        self.txt4.insert(1.0, self.filename4)

    def encrypt(self):
        # messagebox.showinfo('Message', 'Success select file, ' + self.filename)
        if self.filename1 == "":
            messagebox.showinfo('Message', '您还未选择明文文本！')
        elif self.filename2 == "":
            messagebox.showinfo('Message', '您还未选择密钥文本！')
        else:
            mode = self.combobox1.get()
            if mode == 'ECB模式':
                encrypt_AES_file(self.filename1, self.filename2, "ciphertext.txt", 'ECB')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under ECB Mode!')
            elif mode == 'CBC模式':
                encrypt_AES_file(self.filename1, self.filename2, "ciphertext.txt", 'CBC')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under CBC Mode!')
            elif mode == 'CFB模式':
                encrypt_AES_file(self.filename1, self.filename2, "ciphertext.txt", 'CFB')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under CFB Mode!')
            elif mode == 'OFB模式':
                encrypt_AES_file(self.filename1, self.filename2, "ciphertext.txt", 'OFB')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under OFB Mode!')
            else:
                messagebox.showinfo('Message', '您还未选择加密模式！')
                
    def decrypt(self):
        # messagebox.showinfo('Message', 'Success select file, ' + self.filename)
        if self.filename3 == "":
            messagebox.showinfo('Message', '您还未选择密文文本！')
        elif self.filename4 == "":
            messagebox.showinfo('Message', '您还未选择密钥文本！')
        else:
            mode = self.combobox2.get()
            if mode == 'ECB模式':
                decrypt_AES_file(self.filename3, self.filename4, "result.txt", 'ECB')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under ECB Mode!')
            elif mode == 'CBC模式':
                decrypt_AES_file(self.filename3, self.filename4, "result.txt", 'CBC')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under CBC Mode!')
            elif mode == 'CFB模式':
                decrypt_AES_file(self.filename3, self.filename4, "result.txt", 'CFB')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under CFB Mode!')
            elif mode == 'OFB模式':
                decrypt_AES_file(self.filename3, self.filename4, "result.txt", 'OFB')
                messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename1 + ' using password file ' + self.filename2 + ' under OFB Mode!')
            else:
                messagebox.showinfo('Message', '您还未选择加密模式！')

gui = GraphInterface()

# 主消息循环:
gui.mainloop()