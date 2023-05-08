import os.path
import json
import time
from base64 import b64encode, b64decode
from os import path
from os import listdir
import string
import Cryptodome
from Crypto.Random import get_random_bytes
from Crypto.Random.random import sample
from Crypto.Hash import SHA3_512, SHA512
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

master_key = ''
DEFAULT_MASTER_FP: str = 'master.txt'
DEFAULT_CREDENTIALS_FOLDER_FP: str = 'credentials/'
credentials_folder_fp: str = ''

def create_master_pw(master_fp: str=DEFAULT_MASTER_FP):
    # Get input from user to create a new master password
    master_pw = input("No master password found. Enter a new master password: ")
    print('Encoded: ', master_pw.encode())

    # Use a salted hash to store password
    # Salt is an 16 character long alphanumeric string
    salt = "".join(sample(string.ascii_lowercase + string.ascii_uppercase + string.digits, 16))
    salted_pass = master_pw + salt
    print(salted_pass.encode())
    h_obj = SHA3_512.new()
    h_obj.update(salted_pass.encode())
    print('Master password hash created!: ' , h_obj.hexdigest())
    
    # Write salted hash and salt on file
    f = open(master_fp, "w")
    f.write(h_obj.hexdigest() + '\n')
    f.write(salt)
    f.close()
    print('Master password hash stored in ', master_fp)

    # Store password as key for retrieving and adding passwords
    # master_key is global as it will be used for future credential encryption
    global master_key
    master_key = create_master_key(master_pw, salt)
    print("New master password created!")


def verify_master_pw(master_fp: str=DEFAULT_MASTER_FP):
    # Retrieve master password salted hash and salt
    salted_hash_data = retrieve_salted_hash(master_fp)
    salted_hash = salted_hash_data[0]
    salt = salted_hash_data[1]

    print('Master password hash: ', salted_hash)
    print('Master password salt: ', salt)

    # Check if entered password matches the salted hash
    # Ask for master password from user
    # Compare hash from inputted pw and retrieved hash from master_fp
    h_obj = SHA3_512.new()
    while (h_obj.hexdigest() != salted_hash):
        input_master_pw = input("Enter master password: ")
        salted_input_pass = input_master_pw + salt
        print('Your salted input encoded: ', salted_input_pass.encode())
        h_obj = SHA3_512.new()
        h_obj.update(salted_input_pass.encode())
        print('Your inputted salted hash: ', h_obj.hexdigest())

        if (h_obj.hexdigest() == salted_hash):
            print("Correct password! Access granted")
            # Store password as key for retrieving and adding passwords
            global master_key
            master_key = create_master_key(input_master_pw, salt)
        else:
            print("Wrong password! Access denied")


def retrieve_salted_hash(master_fp: str):
    # HELPER FUNCTION for verify_master_pw()
    # Retrieve the salted hash and the corresponding salt
    f = open(master_fp, "r")
    salted_hash = f.readline()[:-1]
    salt = f.readline()
    f.close()   
    return [salted_hash, salt]


def create_master_key(master_pw, salt):
    # Use PBKDF2 to create the master key used for retrieving and adding passwords
    keys = PBKDF2(master_pw, salt.encode(), 32, count=1000000, hmac_hash_module=SHA512)
    key1 = keys[:32]
    return key1


def add_pw(credentials_folder_fp: str=DEFAULT_CREDENTIALS_FOLDER_FP):
    # Get site/app name for the password. Get login (username and password) also.
    app_name: str = input("Enter the website or app the password is for: ")

    # Open a file. If it exists already, ask if user wants to overwrite the existing password
    credentials_fp: str = credentials_folder_fp + app_name + '.json'
    if path.exists(credentials_fp):
        overwrite = input("Password for " + str(app_name) + " exists. Do you wish to overwrite data? (Y/N) ")
        if overwrite.upper() == "Y":
            f = open(credentials_fp, "w")
        else:
            print('Rename app/site name inputted. Not adding any new credentials...')
            return
    else:
        f = open(credentials_fp, "w")

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
    print_pw(app_name)


def print_pw(app_name: str, credentials_folder_fp: str = DEFAULT_CREDENTIALS_FOLDER_FP):
    # HELPER FUNCTION to retrieve password from credential files
    # Check if app name exists. If not, then cancel operation
    credentials_fp: str = credentials_folder_fp + app_name + '.json'
    if path.exists(credentials_fp):
        print(app_name + " credentials found!")

        # Load app name as dictionary
        with open(credentials_fp) as f:
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
            output_error_in_credential_file()
        f.close()
    else: 
        output_file_does_not_exist(app_name)


def output_error_in_credential_file():
    print("Error with file format")


def output_file_does_not_exist(app_name):
    print(app_name + " does not exist!")


def delete_pw():
    # Get app or website name the user wants to retrieve credentials from
    app_name = input("Which website or app do you wish to delete credentials: ")

    if path.exists(app_name + ".json"):
        # Delete the following file
        os.remove(app_name + ".json")
        print(app_name + " credentials entry deleted!")
    else:
        print(app_name + " does not exist!")


def show_all_pws():
    # Get all credentials in credentials/ folder
    pass


def change_master_pw():
    pass


def display_banner(print_cool: bool=True) -> None:
    display_text_list: list = [
        ' ____                 __  __               ____    ___  ',
        '|  _ \ __ _ ___ ___  |  \/  | __ _ _ __   |___ \  / _ \ ',
        '| |_) / _` / __/ __| | |\/| |/ _` |  _ \    __) || | | |',
        '|  __/ (_| \__ \__ \ | |  | | (_| | | | |  / __/ | |_| |',
        '|_|   \__,_|___/___/ |_|  |_|\__,_|_| |_| |_____(_)___/ ',
        '                                                        ',
        "Homealone Specifications, 2023\n"
    ]

    for line in display_text_list:
        if print_cool:
            display_cool(line)
        else:
            print(line)


def display_menu(print_cool: bool=True) -> None:
    display_text_list: list = [
        'Welcome to PassMan 2.0! Here are your options: ',
        '(1) Add a password to the manager',
        '(2) Retrieve a password from the manager',
        '(3) Delete a password from the manager',
        '(4) Show all passwords in the manager',
        '(5) Change master password',
        '(6) Exit'
    ]

    for line in display_text_list:
        if print_cool:
            display_cool(line)
        else:
            print(line)

def display_cool(text: str) -> None:
    print(text)
    time.sleep(0.1)


def main():
    # Create a new master password if a master password already exists
    master_fp: str = DEFAULT_MASTER_FP
    if path.exists(master_fp):
        verify_master_pw()
    else:
        create_master_pw(master_fp=DEFAULT_MASTER_FP)
    
    # Display terminal banner and menu selection
    display_banner()
    display_menu()

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
        elif option == "amogus":
            print("amogus jumpscare!!!!")
        elif option != "6":
            print(option , " is not a valid option. Enter a valid number from the menu below \n \/\/\/\/\/")
            display_menu(print_cool=False)
        option = input("Enter the number of the option you wish to perform: ")
    print("Exiting PassMan 2.0... Good bye :)")
        


if __name__ == "__main__":
    main()