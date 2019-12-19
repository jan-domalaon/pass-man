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
        # Retrieve master password salted hash and salt
        f = open("master.txt", "r")
        salted_hash = f.readline()[:-1]
        salt = f.readline()
        print(salted_hash)
        print(salt)
        f.close()

        # Check if entered password matches the salted hash
        h_obj = SHA3_512.new()
        while (h_obj.hexdigest() != salted_hash):
            input_master_pw = input("Enter master password: ")
            salted_input_pass = input_master_pw + salt
            print(salted_input_pass.encode())
            h_obj = SHA3_512.new()
            h_obj.update(salted_input_pass.encode())
            print(h_obj.hexdigest())
            if (h_obj.hexdigest() == salted_hash):
                print("Access granted!")
            else:
                 print("Access denied!")
    else:
        # Get input from user to create a new master password
        master_pw = input("No master password found. Enter a new master password: ")
        print(master_pw.encode())

        # Use a salted hash to store password
        # Salt is an 8 character long alphanumeric string
        salt = "".join(sample(string.ascii_lowercase + string.ascii_uppercase + string.digits, 8))
        salted_pass = master_pw + salt
        print(salted_pass.encode())
        h_obj = SHA3_512.new()
        h_obj.update(salted_pass.encode())
        print(h_obj.hexdigest())

        # Write salted hash and salt on file
        f = open("master.txt", "w")
        f.write(h_obj.hexdigest() + '\n')
        f.write(salt)
        f.close()

def add_pw():
    pass

def retrieve_pw():
    pass

def delete_pw():
    pass

def show_all_pws():
    pass

def change_master_pw():
    pass

create_master_pw()