import os.path
import json
from base64 import b64encode, b64decode
from os import path
import string
import Cryptodome
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
    # master_key is global as it will be used for future credential encryption
    global master_key
    master_key = create_master_key(master_pw, salt)
    print("New master password created!\n")


def verify_master_pw():
    # Retrieve master password salted hash and salt
    salted_hash_data = retrieve_salted_hash("master.txt")
    salted_hash = salted_hash_data[0]
    salt = salted_hash_data[1]

    print(salted_hash)
    print(salt)

    # Check if entered password matches the salted hash
    # Ask for master password from user and compare hash from inputted pw
    # and retrieved from master.txt
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


def retrieve_salted_hash(master_pw_file):
    # HELPER FUNCTION for verify_master_pw()
    # Retrieve the salted hash and the corresponding salt
    f = open(master_pw_file, "r")
    salted_hash = f.readline()[:-1]
    salt = f.readline()
    f.close()   
    return [salted_hash, salt]


def create_master_key(master_pw, salt):
    # Use PBKDF2 to create the master key used for retrieving and adding passwords
    keys = PBKDF2(master_pw, salt.encode(), 32, count=1000000, hmac_hash_module=SHA512)
    key1 = keys[:32]
    return key1


def add_pw():
    # Get site/app name for the password. Get login (username and password) also.
    app_name    = input("Enter the website or app the password is for: ")

    # Open a file. If it exists already, ask if user wants to overwrite the existing password
    if path.exists(str(app_name) + ".json"):
        overwrite = input("Password for " + str(app_name) + " exists. Do you wish to overwrite data? (Y/N) ")
        if overwrite.upper() == "Y":
            f = open(str(app_name) + ".json", "w")
    else:
        f = open(str(app_name) + ".json", "w")

    # Get credentials
    entries = input_credentials()
    json_entries = ["Username", "Password"]

    # Construct output json format
    output_json = create_output_json(json_entries)

    # Add nonce on encrypted message. Each entry has a different nonce.
    for i in range(0, len(json_entries)):
        # Use entered password as key for encrypting
        cipher = AES.new(master_key, AES.MODE_EAX)
        ct_bytes, tag = cipher.encrypt_and_digest(entries[i].encode())

        # Write to file. There should be the length of entries * 3
        # Times 3 because of ciphertext, tag, and nonce
        json_k = [ 'nonce', 'ciphertext', 'tag' ]
        json_v = []
        for x in [cipher.nonce, ct_bytes, tag]:
            json_v.append(b64encode(x).decode('utf-8'))
        entry_json = json.dumps(dict(zip(json_k, json_v)))
        print("Entry json: ", entry_json)
        output_json[json_entries[i]] = entry_json
    # Output to file
    json.dump(output_json, f)
    print("output json: ", output_json)
    f.close()
    print("New login credentials for " + app_name + " added!")


def input_credentials():
    # HELPER FUNCTION: meant to get user input for credentials
    # Currently, the only credentials are user name and password
    user_name   = input("Enter the username used for this website or app: ")
    app_pw      = input("Enter the password for this website or app: ")
    credentials = [user_name, app_pw]
    return credentials


def create_output_json(entries):
    # HELPER FUNCTION to create the output json
    # Takes in entries to create credentials json
    # Value meant to be populated with entry_json
    output_json = {}
    for entry in entries:
        output_json[entry] = ""
    return output_json


def retrieve_pw():
    # Get app or website name the user wants to retrieve credentials from
    app_name = input("Which website or app do you wish to retrieve credentials from: ")

    # Check if app name exists. If not, then cancel operation
    if path.exists(str(app_name) + ".json"):
        print(app_name + " credentials found!")

        # Load app name as dictionary
        with open(str(app_name) + ".json") as f:
            encrypted_json = json.load(f)
        
        # Get each entry in encrypted_json and print entry value
        try:
            for entry in encrypted_json.keys():
                # Keys expected from an entry
                json_k = ["nonce", "ciphertext", "tag"]
                json_v = {}
                # Value of each credential is stored as a string that needs to change to dict
                entry_json = json.loads(encrypted_json[entry])

                # Populate each value of key. Stored in json_v
                for k in json_k:
                    json_v[k] = b64decode(entry_json[k])

                # Finally decipher with the given nonce, ciphertext, and tag
                cipher = AES.new(master_key, AES.MODE_EAX, nonce=json_v['nonce'])
                plaintext = cipher.decrypt_and_verify(json_v['ciphertext'], json_v['tag'])
                print(entry + ": ", plaintext.decode())
        except (ValueError, KeyError):
            print("Error with file format")
        f.close()
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
    print("By Jan Domalaon, 2020\n")

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