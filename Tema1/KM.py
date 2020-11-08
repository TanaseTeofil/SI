import threading
import socket
import codecs
from utils import validate_crypt_method
from utils import XOR
from Crypto.Cipher import AES
from base64 import b64encode

key1 = 'FJ32ABG21V1JNRA12SIMP5ST98EF00AN'

key2 = 'POG6A87E21LLL404PLS11SEND22HELP3'

key3 = '42KM2STEPSA4W4YFR0MK11L1NGMYS3LF'

def s_Key(connect, obtained, node):
    crypt_type = obtained.split()[-1].decode()
    if validate_crypt_method(crypt_type):
        print("Received from {} ".format(node) + crypt_type + " as crypt type")
        if str(crypt_type).upper().endswith("ECB"):
            key1 = encrypt_ECB_K().decode()
            try:
            	connect.sendall("[KM] [KEY1]: {}".format(str(key1)).encode())
            except socket.error:
                print ("Error on socket sendall.")
                sys.exit(1)
        else:
            key2 = encrypt_OFB_K().decode()
            try:
            	connect.sendall("[KM] [KEY2]: {}".format(str(key2)).encode())
            except socket.error:
                print ("Error on socket sendall.")
                sys.exit(1)


def getMsg_A(connect):
    while True:
        obtained = connect.recv(1024)
        if not obtained:
            break
        if obtained == '':
            pass
        else:
            s_Key(connect, obtained, "A")


def getMsg_B(connect):
    while True:
        obtained = connect.recv(1024)
        if not obtained:
            break
        if obtained == '':
            pass
        else:
            s_Key(connect, obtained, "B")


def encrypt_ECB_K():
    global key3
    cipher = AES.new(key3.encode('utf8'), AES.MODE_ECB)
    return b64encode(cipher.encrypt(key1.encode('utf-8')))


def encrypt_OFB_K():
    global key3
    iv = '0' * 16
    cipher = AES.new(key3.encode('utf8'), AES.MODE_ECB)
    iv = cipher.encrypt(iv)
    enc = XOR(key2.encode('utf-8'), iv)
    return b64encode(enc)


if __name__ == '__main__':
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
    	s.bind(('', 9000))
    except socket.error:
        print ("Couldn't bind socket.")
        sys.exit(1)
    try:
    	s.listen(10)
    except socket.error:
        print ("Error while listening on socket.")
        sys.exit(1)

    print("Listening on PORT = 9000")

    connection = 0
    
    while True:
        (connect, addr) = s.accept()
        if connection == 0:
            thread1 = threading.Thread(target=getMsg_B, args=([connect]))
        else:
            thread1 = threading.Thread(target=getMsg_A, args=([connect]))
        connection += 1
        try:
            thread1.start()
        except KeyboardInterrupt:
            thread1.join()
            connect.close()
            break