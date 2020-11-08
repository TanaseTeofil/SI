import codecs
import socket
import threading
from base64 import b64encode
from Crypto.Cipher import AES


def pad(txt):
    if len(txt) % 16 == 0:
        return txt
    pad_data = txt + (16 - (len(txt) % 16)) * b'\x00'
    return pad_data


def XOR(input, key):
    index = 0
    output_bytes = b''
    for byte in input:
        if index >= len(key):
            index = 0
        output_bytes += bytes([byte ^ key[index]])
        index += 1
    return output_bytes


def validate_crypt_method(crypt_type):
    crypt_type = str(crypt_type)
    if crypt_type.upper().endswith("ECB"):
        return True
    elif crypt_type.upper().endswith("OFB"):
        return True
    return False
