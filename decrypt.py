#!/usr/bin/python3

import os
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

BACKUP = '/usr/home/aharon/.backup/decrypt_bkup.txt'

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding

def main():
    if len(sys.argv) != 3:
        print("usage: {} filename password".format(sys.argv[0]))
        exit(1)
    f = open(sys.argv[1],'r')
    crypt = f.read()
    f.close()
    passwd = sys.argv[2].encode()
    try:
        text = decrypt(passwd, crypt)
    except ValueError:
        print('probably you entered wrond password :( \nplease try again\n')
        exit(2)
    text = text.decode()
    print('the decrypted file content is: {}'.format(text))
    print('would you like to save it?')
    confirm = input('y/n \n')
    if confirm[0] == 'y':
        backup(crypt)
        print('saving file at: {}'.format(os.path.realpath(sys.argv[1])))
        f = open(sys.argv[1],'w')
        f.write(text)
        f.close()
        print("don't worry you have backup of the file on: {}\n".format(BACKUP))
    
def backup (content):
    f = open(BACKUP, 'w')
    f.write(content)
    f.close()


if __name__ == '__main__':
    main()
