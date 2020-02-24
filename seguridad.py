#Clase Seguridad para encriptar y desencriptar.
from pyDes import * 
class Seguridad:
    #<summary>
    #Constructor que inicializa la llave.
    #</summary>
    def __init__(self):
        self.llave="5166647731464e3873614851666d487868714e52"

    #<summary>
    #Metodo que encripta un dato con el algoritmo Triple DES Modo ECB. 
    #</summary>
    #<param name="self">Objeto de inicializacion de la clase.</param>
    #<param name="dato">Dato a encriptar.</param>
    #<returns>Retorna el mensaje encriptado en formato hexadecimal.</returns>
    def Encriptar(self, dato):
        try:
            m_Operacion = triple_des(self.llave[:24], ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
            m_DatoEncriptado = m_Operacion.encrypt(dato) 
            print(type(m_DatoEncriptado))
            print ("Encrypted: %r" % m_DatoEncriptado )
            print ("Hexa: " + m_DatoEncriptado.hex())
            return m_DatoEncriptado.hex().upper()    
        except ValueError as e:
            print("ERROR Seguridad - Encriptar: ", e)
        return ""

    #<summary>
    #Metodo que desencripta un dato con el algoritmo Triple DES Modo ECB. 
    #</summary>
    #<param name="self">Objeto de inicializacion de la clase.</param>
    #<param name="dato">Dato a encriptar.</param>
    #<returns>Retorna el mensaje desencriptado en texto plano.</returns>
    def DesEncriptar(self, dato):
        try:
            m_Operacion = triple_des(self.llave[:24], ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
            m_DatoDesEncriptado = m_Operacion.decrypt(bytearray.fromhex(dato))     
            print ("Decrypted: %r" % m_DatoDesEncriptado)
            return m_DatoDesEncriptado.decode()  
        except ValueError as e:
            print("ERROR Seguridad - DesEncriptar: ", e)
        return ""