import socket
import os
import nacl.utils
from Crypto.Cipher import AES
from nacl.signing import SigningKey
import json
from nacl import pwhash, secret, utils
import datetime
import tkinter.filedialog



class randomPynacl():
    def __init__(self, bytes):
        self._bytes = bytes
        self._buf= nacl.utils.random(self._bytes)
    
    def changeBits(self,bytes):
        self._bytes = bytes
    
    def Random(self):
        self._buf= nacl.utils.random(self._bytes)

    def PrintRandom(self):
        for number in self._buf:
            print(f'{hex(number)[2:]}',end = " ")
    
    def strRandom(self):
        random=''
        for number in self._buf:
            if len(hex(number)[2:])==1:
                random+="0"
            random+= hex(number)[2:]
            random+= ""
        return random

class login():
    def login(userlogin,password): #se manda el usuario y contraseña a verificar
        login=False
        #se abre el archivo donde estan los usuarios y las contraseñas
        with open('users.json') as file: 
            data = json.load(file)
            #una vez abierto el archivo se verifica si existe el usuario
            for userdata in data['users']:
                if userdata['user']==userlogin:
                    #si el usuario existe se usa pwhash.verify para comparar la contraseña ingresada con la encriptada en el archivo
                    try:
                        login=nacl.pwhash.verify(userdata['password'].encode(), password.encode())
                    except:
                        print("Bad password")
        return login


class DataLogger:
    #se guarda cual sera el nombre ddel archivo donde se guardaran los logs
    def __init__(self, path:str):
        self.path=path
    #se escribe en el archivo el log con fecha usuario y si el login fue true o false
    def write_to_log(self,text:str,status:str):
        file = open(self.path, 'a')
        file.write(f'{datetime.datetime.now()}:Usuario {text} estado: {status}\n')

#se abre el archivo de logs
datalog= DataLogger("log.txt")
# se crea el socket para el servidor
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#se pone el host de mi localhost y el port 5500 (es el que tengo configurado) 
host="127.0.0.1"
port=5500
#se le asigna al servidor el host y el puerto
serversocket.bind((host,port))
#se configura para que empiece a escuchar
serversocket.listen(3)
print(f'El servidor esta escuchando en {host} puerto {port}')
while True: #siempre se estara escuchando
    # se aceptan conexiones del exterior
    (clientsocket, address) = serversocket.accept()
    print(f'Se ha conectado con el cliente {address}')
    #antes de mandar el archivo se verifica con cliente-contraseña si es un usuario valido
    user= False
    while user == False :
        userName= input('UserName: ').strip()
        passWord = input('Password: ').strip()
        user=login.login(userName,passWord)
        #se guarda en el archivo de log quien intento entrar y si fue correcto su password
        datalog.write_to_log("LOGIN "+ userName,user)
    #Una vez que se ha verificado el passwrod y contraseña se escoge el archivo a mandar
    FILE = tkinter.filedialog.askopenfilename()
    ENCRIPTADOYFRIMADO = "Encriptado.txt"
    DESENCRIPTADO = "Desencriptado.txt"
    #se crea el random que se utilizara
    random=randomPynacl(16)
    random=random.strRandom()
    #se asgignan los valores que se utilizan en el AES
    key = random.encode()
    cipher = AES.new(key, AES.MODE_EAX)
    d_cipher=AES.new(key, AES.MODE_EAX, cipher.nonce)
    #el archivo se abre y se guarda la data en original
    with open(FILE, 'rb') as file:
        original = file.read()
    #se encripta el data del archivo
    cipherfile = cipher.encrypt(original)
    #se genera la firma 
    signature_key= SigningKey.generate()
    #se firma el archivo
    signedfile=signature_key.sign(cipherfile)
    #se sobre-escribe el archivo con el data encriptado y firmado
    with open(ENCRIPTADOYFRIMADO, 'wb') as encrypted_file:
        encrypted_file.write(signedfile)
    with clientsocket:
        #se manda el archivo
        with open(FILE, 'rb') as f:
            clientsocket.sendfile(f)
            print("El archivo se ha enviado")
    # se verifica la firma, despues de esto quedara el archivo como antes de ser
    verified = signature_key.verify_key.verify(signedfile)
    #se desencripta para checar que este correcta la encriptacion esto se poede comentar para checar que los dos archivos coinciden cuando estan encriptados
    decrypted = d_cipher.decrypt(verified)
    with open(DESENCRIPTADO, 'wb') as dec_file:
        dec_file.write(decrypted)

