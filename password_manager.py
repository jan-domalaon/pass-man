import os.path
from os import path
import Cryptodome
import string
from Crypto.Random import get_random_bytes
from Crypto.Random.random import sample
from Crypto.Hash import SHA3_512


def create_master_pw():
    # Create salt (if not existing already)
    if path.exists("master.txt"):
        pass
    else:
        # Get input from user to create a new master password
        master_pw = input("No master password found. Enter a new master password: ")
        print(master_pw.encode())

        
        # Use a salted hash to store password
        f = open("master.txt", "w")
        salt = "".join(sample(string.ascii_lowercase + string.ascii_uppercase + string.digits, 8))
        str.encode(master_pw + salt)
        h_obj = SHA3_512.new()
        h_obj.update(master_pw + salt)
        f.close()

def add_pw():
    pass

def retrieve_pw():
    pass

def delete_pw():
    pass

def show_all_pws():
    pass

create_master_pw()