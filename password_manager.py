import os.path
from os import path
import Cryptodome
import string
from Crypto.Random import get_random_bytes
from Crypto.Random.random import sample
from Crypto.Hash import SHA3_512, SHA512
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

master_key = ''


def create_master_pw():
    # Get input from user to create a new master password
    master_pw = input("No master password found. Enter a new master password: ")
    print(master_pw.encode())

    # Use a salted hash to store password
    # Salt is an 16 character long alphanumeric string
    salt = "".join(sample(string.ascii_lowercase + string.ascii_uppercase + string.digits, 16))
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

    # Store password as key for retrieving and adding passwords
    global master_key
    master_key = create_master_key(master_pw, salt)
    print("New master password created!\n")


def verify_master_pw():
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
            # Store password as key for retrieving and adding passwords
            global master_key
            master_key = create_master_key(input_master_pw, salt)
            print("master key ", master_key)
        else:
            print("Access denied!")


def create_master_key(master_pw, salt):
    # Use PBKDF2 to create the master key used for retrieving and adding passwords
    keys = PBKDF2(master_pw, salt.encode(), 32, count=1000000, hmac_hash_module=SHA512)
    key1 = keys[:32]
    return key1


def add_pw():
    # Get site/app name for the password. Get login (username and password) also.
    app_name    = input("Enter the website or app the password is for: ")

    # Open a file. If it exists already, ask if user wants to overwrite the existing password
    if path.exists(str(app_name) + ".txt"):
        overwrite = input("Password for " + str(app_name) + " exists. Do you wish to overwrite data? (Y/N) ")
        if overwrite.upper() == "Y":
            f = open(str(app_name) + ".txt", "wb")
    else:
        f = open(str(app_name) + ".txt", "wb")

    # Get credentials
    user_name   = input("Enter the username used for this website or app: ")
    app_pw      = input("Enter the password for this website or app: ")
    entries = [user_name, app_pw]

    # Use entered password as key for encrypting
    # print("master key in add pw ", master_key)
    cipher = AES.new(master_key, AES.MODE_EAX)

    # Add nonce on encrypted message. Each entry has a different nonce.
    for entry in entries:
        nonce = get_random_bytes(16)
        cipher.nonce = nonce
        ciphertext = cipher.encrypt(entry.encode())
        print("ciphertext: ", ciphertext)
        print("nonce: ", cipher.nonce)
        # Write to file. 4 Entries: app username, its nonce, app password, its nonce
        f.write(ciphertext + b"\n")
        f.write(nonce + b"\n")
    f.close()
    print("New login credentials for " + app_name + " added!")


def retrieve_pw():
    # Get app or website name the user wants to retrieve credentials from
    app_name = input("Which website or app do you wish to retrieve credentials from: ")
    if path.exists(str(app_name) + ".txt"):
        print(app_name + " credentials found!")
    else: 
        print(app_name + " does not exist!")


def delete_pw():
    pass


def show_all_pws():
    pass


def change_master_pw():
    pass


def main():
    # Create a new master password if a master password already exists
    if path.exists("master.txt"):
        verify_master_pw()
    else:
        create_master_pw()
    
    print(" _____                __  __             \n"
    "|  __ \              |  \/  |            \n"
    "| |__) |_ _ ___ ___  | \  / | __ _ _ __  \n"
    "|  ___/ _` / __/ __| | |\/| |/ _` | '_ \ \n"
    "| |  | (_| \__ \__ \ | |  | | (_| | | | |\n"
    "|_|   \__,_|___/___/ |_|  |_|\__,_|_| |_|\n")
    print("By Jan Domalaon, 2019\n")

    print("Welcome to PassMan. Here are the options: \n" + 
            "(1) Add a password to the manager \n" +
            "(2) Retrieve a password from the manager \n" +
            "(3) Delete a password from the manager \n" + 
            "(4) Show all passwords in the manager \n" +
            "(5) Change master password \n" +
            "(6) Exit \n")
    option = input("Enter the number of the option you wish to perform: ")
    while option != "6":
        if option == "1":
            add_pw()
        elif option == "2":
            retrieve_pw()
        elif option == "3":
            delete_pw()
        elif option == "4":
            show_all_pws()
        elif option == "5":
            change_master_pw()
        option = input("Enter the number of the option you wish to perform: ")
    print("Exiting PassMan... Good bye :)")
        


if __name__ == "__main__":
    main()