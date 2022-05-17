import socket

#se pone el host de mi localhost y el port que tiene el servidor al que se conectara
host="127.0.0.1"
port=5500
FILE = "Mundo.txt"
CHUNK_SIZE = 1024
# se crea el socket para el cliente
clientso = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#se conecta al servidor
clientso.connect((host,port))
#se recibe el archivo y se guarda en el file configurado
with open(FILE, "wb") as f:        
        chunk = clientso.recv(CHUNK_SIZE)
        while chunk:
            f.write(chunk)
            chunk = clientso.recv(CHUNK_SIZE)
        print("Archivo recibido")