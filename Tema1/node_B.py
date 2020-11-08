import socket
import threading
from base64 import b64decode
from Crypto.Cipher import AES
from utils import validate_crypt_method
from utils import pad
from utils import XOR

LH_KM = 'localhost'
P_KM = 9000
key3 = '42KM2STEPSA4W4YFR0MK11L1NGMYS3LF'
iv = '0' * 16

def getMsg_A(connect):
    global iv
    global crypt_type
    txt = []
    while True:
        obtained = connect.recv(1024)
        obtained = obtained.decode()
        if not obtained:
            break
        if obtained == ' ':
            pass
        else:
            if "[MODE]" in obtained:
                iv = '0' * 16
                txt = []
                crypt_type = obtained.split()[-1]
                if validate_crypt_method(crypt_type):
                    print("Received from A encryption method: " + crypt_type)
                    try:
                        s_km.sendall("[B] [KEY]: {}".format(crypt_type).encode())
                    except socket.error:
                        print ("Error on socket sendall.")
                        sys.exit(1)
                else:
                    try:
                        connect.sendall("[B] [ERROR]: Encryption method inexistent. Try again.".encode())
                    except socket.error:
                        print ("Error on socket sendall.")
                        sys.exit(1)
            else:
                obtained = obtained[:]
                if crypt_type == "ECB":
                    for i in range(len(obtained) // 25):
                        print(obtained[25 * i:25 * (i + 1)])
                        decrypted = decrypt_ECB_T(obtained[25 * i:25 * (i+1)])
                        txt.append(decrypted)
                        print("Text Decrypted: {}\n".format(decrypted))
                else:
                    for i in range(len(obtained) // 25):
                        print(obtained[25 * i:25 * (i + 1)])
                        decrypted = decrypt_OFB_T(obtained[25 * i:25 * (i+1)])
                        txt.append(decrypted)
                        print("Text Decrypted: {}".format(decrypted))
                print('Status text: {}'.format("".join(txt)))


def getMsg_KM(connect):
    global key_decrypted
    while True:
        obtained = connect.recv(1024)
        obtained = obtained.decode()
        if not obtained:
            break
        if obtained == ' ':
            pass
        else:
            print(obtained)
            key = obtained.split()[-1]
            if crypt_type == "ECB":
                key_decrypted = decrypt_ECB_K(key)
                print("Key Decrypted: {}".format(key_decrypted))
                s_Msg(connect)
            else:
                key_decrypted = decrypt_OFB_K(key)
                print("Key Decrypted: {}".format(key_decrypted))
                s_Msg(connect)


def s_Msg(connect):
    connect.sendall("[B]: Start".encode())



def decrypt_ECB_T(text):
    global key_decrypted
    text = b64decode(text)
    cipher = AES.new(key_decrypted.encode('utf8'), AES.MODE_ECB)
    return cipher.decrypt(text).decode('utf8')


def decrypt_OFB_T(text):
    global key_decrypted
    global iv
    cipher = AES.new(key_decrypted.encode('utf8'), AES.MODE_ECB)
    iv = cipher.encrypt(iv)
    decrypt = XOR(b64decode(text), iv)
    return decrypt.decode('utf-8')


def decrypt_ECB_K(key):
    return AES.new(key3.encode('utf8'), AES.MODE_ECB).decrypt(b64decode(key)).decode('utf8')


def decrypt_OFB_K(key):
    iv = '0' * 16
    cipher = AES.new(key3.encode('utf8'), AES.MODE_ECB)
    iv = cipher.encrypt(iv)
    decrypt = XOR(b64decode(key), iv)
    return decrypt.decode('utf8')


if __name__ == '__main__':
    crypt_type = ''
    key_decrypted = ''

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print ("Couldn't create socket.")
        sys.exit(1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error:
        print ("Couldn't set socket output.")
        sys.exit(1)
    try:
        s.bind(('', 9500))
    except socket.error:
        print ("Couldn't bind socket.")
        sys.exit(1)
    try:
        s.listen(10)
        print("Listening on localhost, PORT = 9000")
    except socket.error:
        print ("Error while listening on socket.")
        sys.exit(1)
    
    try:
        (connect, addr) = s.accept()
    except socket.error:
        print ("Error on socket accept.")
        sys.exit(1)

    try:
        s_km = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print ("Couldn't create socket.")
        sys.exit(1)
    try:
        s_km.connect((LH_KM, P_KM))
    except socket.error:
        print ("Couldn't connect to socket.")
        sys.exit(1)
    
    
    thread1 = threading.Thread(target=getMsg_A, args=([connect]))
    
    thread2 = threading.Thread(target=s_Msg, args=([connect]))
    
    thread3 = threading.Thread(target=getMsg_KM, args=([s_km]))
   
    
    try:
        
        thread1.start()
        
        thread2.start()
        
        thread3.start()
        
    
    except KeyboardInterrupt:
        thread1.join()
        thread2.join()
        thread3.join()