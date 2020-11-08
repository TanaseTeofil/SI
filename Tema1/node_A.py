import codecs
import socket
import threading
from base64 import b64decode
from Crypto.Cipher import AES
from utils import pad
from utils import XOR

key3 = '42KM2STEPSA4W4YFR0MK11L1NGMYS3LF'

LH_B = 'localhost'
P_B = 9500

LH_KM = 'localhost'
P_KM = 9000

iv = bytearray(16)

r_file = ''


def obtain_KM(s_km, s):
    while True:
        obtained = s_km.recv(1024)
        obtained = obtained.decode()
        if not obtained:
            break
        else:
            key = obtained.split()[-1]
            if crypt_type == "ECB":
                key_decrypted = decrypt_ECB_K(key)
                s_txt(s, key_decrypted)
            else:
                key_decrypted = decrypt_OFB_K(key)
                s_txt(s, key_decrypted)


def obtain_B(s):
    global st_comms
    while True:
        try:
            r_msg = s.recv(1024).decode()
            if not r_msg:
                break
            else:
                if "Start" in r_msg:
                    st_comms = 1
        except:
            raise
            break


def s_txt(s, key_dec):
    global r_file
    with open(r_file, "rb") as fd:
        text = fd.read()
        if crypt_type == "ECB":
            encrypt_ECB_K(text, key_dec, s)
        elif crypt_type == "OFB":
            encrypt_OFB_K(text, key_dec, s)


def s_message(s, s_km):
    global r_file
    global crypt_type
    while True:
        crypt = input("Write encryption method (ECB | OFB): ")
        r_file = input("File name to crypt: ")
        if crypt == '':
            pass
        else:
            if crypt.upper().strip() == "ECB":
                crypt_type = crypt
                try:
                    try:
                        s.sendall("[A] [MODE]: {}".format(crypt).encode())
                    except socket.error:
                        print ("Error on socket sendall.")
                        sys.exit(1)
                    try:
                        s_km.sendall("[A] [KEY-A]: {}".format(crypt).encode())
                    except socket.error:
                        print ("Error on socket sendall.")
                        sys.exit(1)
                except:
                    raise
            elif crypt.upper().strip() == "OFB":
                crypt_type = crypt
                try:
                    try:
                        s.sendall("[A] [MODE]: {}".format(crypt).encode())
                    except socket.error:
                        print ("Error on socket sendall.")
                        sys.exit(1)
                    try:
                        s_km.sendall("[A] [KEY-A]: {}".format(crypt).encode())
                    except socket.error:
                        print ("Error on socket sendall.")
                        sys.exit(1)
                except:
                    raise
            else: print("Encryption method inexistent.")


def encrypt_ECB_K(txt, key, s):
    txt = pad(txt)
    cipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    for block in range(len(txt) // 16 ):
        block_enc = cipher.encrypt(txt[16 * block:16 * (block + 1)])
        try:
            s.sendall(codecs.encode(block_enc, 'base64'))
        except socket.error:
            print ("Error on socket sendall.")
            sys.exit(1)


def decrypt_ECB_K(key):
    return AES.new(key3.encode('utf8'), AES.MODE_ECB).decrypt(b64decode(key)).decode('utf8')


def encrypt_OFB_K(txt, key, s):
    global iv
    txt = pad(txt)
    cipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    iv = '0' * 16
    for b in range(len(txt) // 16 ):
        iv = cipher.encrypt(iv)
        enc = XOR(txt[b * 16: (b + 1) * 16], iv)
        s.sendall(codecs.encode(enc, 'base64'))


def decrypt_OFB_K(key):
    iv = '0' * 16
    cipher = AES.new(key3.encode('utf8'), AES.MODE_ECB)
    iv = cipher.encrypt(iv)
    decrypt = XOR(b64decode(key), iv)
    return decrypt.decode('utf8')


if __name__ == '__main__':

    st_comms = 0
    crypt_type = ''

    try:
        sock_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print ("Couldn't create socket")
        sys.exit(1)
    try:
        sock_KM = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print ("Couldn't create socket")
        sys.exit(1)

    try:
        sock_B.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error:
        print ("Couldn't set socket output.")
        sys.exit(1)
    try:
        sock_KM.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error:
        print ("Couldn't set socket output.")
        sys.exit(1)

    try:
        sock_B.connect((LH_B, P_B))
    except socket.error:
        print ("Couldnt connect with the socket-server")
        sys.exit(1)
    try:
        sock_KM.connect((LH_KM, P_KM))
    except socket.error:
        print ("Couldnt connect with the socket-server")
        sys.exit(1)

    
    thread1 = threading.Thread(target=obtain_B, args=([sock_B]))
    
    thread2 = threading.Thread(target=obtain_KM, args=([sock_KM, sock_B]))
    
    thread3 = threading.Thread(target=s_message, args=([sock_B, sock_KM]))
    

    try:
        
        thread1.start()
        
        thread2.start()
       
        thread3.start()
        
    except:
        
        thread1.join()
        
        thread2.join()
       
        thread3.join()
        
        try:
            sock_B.close()
        except socket.error:
            print ("Couldn't close socket")
            sys.exit(1)
        
        try:
            sock_KM.close()
        except socket.error:
            print ("Couldn't close socket")
            sys.exit(1)
