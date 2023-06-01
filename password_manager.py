import os.path
import json
import time
from base64 import b64encode, b64decode
from os import path
from os import listdir
from os.path import isfile, join
import string
import Cryptodome
import shutil
from Crypto.Random import get_random_bytes
from Crypto.Random.random import sample
from Crypto.Hash import SHA3_512, SHA512
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from datetime import datetime

master_key = ''
old_master_key = ''
DEFAULT_MASTER_FP: str = 'master.txt'
DEFAULT_CREDENTIALS_FOLDER_FP: str = 'credentials\\'
DEFAULT_BACKUP_FOLDER_FP: str = 'backup\\'
DEFAULT_MAX_ATTEMPT: int = 5
DEFAULT_OLD_MASTER_FP: str = 'master_old.txt'
credentials_folder_fp: str = ''

def create_master_pw(master_fp: str=DEFAULT_MASTER_FP):
    # Get input from user to create a new master password
    master_pw = input("Enter a new master password: ")
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


def challenge_master_pw(master_fp: str=DEFAULT_MASTER_FP) -> bool:
    # Check if entered password matches the salted hash
    # Ask for master password from user
    # Compare hash from inputted pw and retrieved hash from master_fp
    # 5 attempts only. Then, program closes.
    attempt_count: int = 0

    # Print master salt and hash
    master_salted_hash_list = retrieve_salted_hash(master_fp)
    print('Master password hash: ', master_salted_hash_list[0])
    print('Master password salt: ', master_salted_hash_list[1])   

    while attempt_count < DEFAULT_MAX_ATTEMPT:
        input_master_pw = input("Enter master password: ")
        if verify_master_pw(input_master_pw):
            print("Correct password! Access granted.")
            clear_terminal(5)
            return True
        else:
            attempt_count += 1
            print_wrong_attempt_prompt(attempt_count)
    display_end_program()
    return False


def print_wrong_attempt_prompt(attempt_count: int) -> None:
    print("Wrong password! Access denied.")
    print("You have done ", attempt_count , " out of ", DEFAULT_MAX_ATTEMPT, " max attempts.")
    if attempt_count == DEFAULT_MAX_ATTEMPT - 1:
        print("This is your last attempt! The program will end if you get this wrong.")


def verify_master_pw(pw_attempt: str, master_fp: str=DEFAULT_MASTER_FP) -> bool:
    # HELPER FUNCTION FOR challenge_master_pw()
    # Without the terminal print statements
    salted_hash_data = retrieve_salted_hash(master_fp)
    salted_hash = salted_hash_data[0]
    salt = salted_hash_data[1]

    # Check if entered password matches the salted hash
    # Ask for master password from user
    # Compare hash from inputted pw and retrieved hash from master_fp
    h_obj = SHA3_512.new()
    salted_input_pass = pw_attempt + salt
    h_obj = SHA3_512.new()
    h_obj.update(salted_input_pass.encode())

    if (h_obj.hexdigest() == salted_hash):
        # Store password as key for retrieving and adding passwords
        global master_key
        master_key = create_master_key(pw_attempt, salt)
        return True
    else:
        return False


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


def create_output_json(entries: list):
    # HELPER FUNCTION to create the output json
    # Takes in entries to create credentials json
    # Value meant to be populated with entry_json
    output_json = {}
    for entry in entries:
        output_json[entry] = ""
    return output_json


def encrypt_pw_to_json(credentials_dict: dict, creds_json_fp: str) -> None:
    # Encrypt credentials to a json file with a given credentials dict

    # Output_json is just a dictionary with all the keys of the credentials_dict, but with no value. A template
    output_json: dict = create_output_json(entries=credentials_dict.keys())

    f = open(creds_json_fp, 'w')
    for entry_name in credentials_dict.keys():
        output_json
        # Use entered password as key for encrypting
        cipher = AES.new(master_key, AES.MODE_EAX)
        ct_bytes, tag = cipher.encrypt_and_digest(credentials_dict[entry_name].encode())

        # Write to file. There should be the length of entries * 3
        # Times 3 because of ciphertext, tag, and nonce
        json_k = [ 'nonce', 'ciphertext', 'tag' ]
        json_v = []
        for x in [cipher.nonce, ct_bytes, tag]:
            json_v.append(b64encode(x).decode('utf-8'))
        entry_json = json.dumps(dict(zip(json_k, json_v)))
        output_json[entry_name] = entry_json
    json.dump(output_json, f)
    f.close()
    print("New login credentials for " + creds_json_fp + " added!")


def retrieve_pw():
    # Get app or website name the user wants to retrieve credentials from
    app_name = input("Which website or app do you wish to retrieve credentials from: ")
    print_pw(app_name)


def print_pw(app_name: str, credentials_folder_fp: str = DEFAULT_CREDENTIALS_FOLDER_FP):
    # HELPER FUNCTION to retrieve password from credential files
    # Check if app name exists. If not, then cancel operation
    credentials_fp: str = credentials_folder_fp + app_name + '.json'
    credentials_dict: dict = decrypt_credentials_file(credentials_fp, app_name, master_key)

    # Catch if dictionary is empty
    if credentials_dict is not None:
        for entry in credentials_dict.keys():
            print(entry, ': ', credentials_dict[entry])


def decrypt_credentials_file(credentials_fp: str, app_name: str, decrypt_master_key) -> dict:
    # Decrypts the credentials file. Return as a dict
    credentials_dict = {}
    if path.exists(credentials_fp):
        print(credentials_fp + " found!")

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
                cipher = AES.new(decrypt_master_key, AES.MODE_EAX, nonce=json_v['nonce'])
                plaintext = cipher.decrypt_and_verify(json_v['ciphertext'], json_v['tag'])
                credentials_dict[entry] = plaintext.decode()
        except (ValueError, KeyError):
            output_error_in_credential_file()
            return None
        f.close()
    else: 
        output_file_does_not_exist(app_name)
        return None
    return credentials_dict


def output_error_in_credential_file():
    print("Error with file format. Returning to menu...")


def output_file_does_not_exist(app_name):
    print(app_name + " does not exist! Returning to menu...")


def delete_pw():
    # Get app or website name the user wants to retrieve credentials from
    app_name = input("Which website or app do you wish to delete credentials: ")

    if path.exists(app_name + ".json"):
        # Delete the following file
        os.remove(app_name + ".json")
        print(app_name + " credentials entry deleted!")
    else:
        print(app_name + " does not exist!")


def show_all_pws(credentials_fp: str=DEFAULT_CREDENTIALS_FOLDER_FP):
    # Get all credentials in a credentials folder
    creds_filenames = get_files_in_folder(credentials_fp)
    print("Files found in folder ", credentials_fp)
    print(creds_filenames)

    # Get only json files. Most likely to be credential files
    json_file_names = get_json_filenames(creds_filenames)

    for file_name in json_file_names:
        # App name is the file name without .json suffix
        app_name = file_name[0:-5]
        print_pw(app_name=app_name)


def get_files_in_folder(folder_fp: str) -> list:
    return [f for f in listdir(folder_fp) if isfile(join(folder_fp, f))]


def get_json_filenames(file_names: list) -> list:
    json_file_names = []
    for file_name in file_names:
        try:
            if file_name[-5:] == '.json':
                json_file_names.append(file_name)
        except:
            print('File exception occurred')
    return json_file_names


def menu_change_master_pw(master_fp: str=DEFAULT_MASTER_FP, credentials_fp: str=DEFAULT_CREDENTIALS_FOLDER_FP, backup_fp: str=DEFAULT_BACKUP_FOLDER_FP) -> None:
    # Ask for master password again to do
    master_pw_attempt = input("As a safety precaution, enter the master password again: ")
    if verify_master_pw(master_pw_attempt):
        # Add precaution
        precaution = input(
            "Note: this will change the master key for all of your stored credentials. If you forget your new master password, you can use your old master password by choosing the old master file, stored in the backup/ folder. The backup folder will contain old credentials and master files. They will be stored in folders with the date and time they were backed up. \n Do you understand this? (Y/N): "
            )
        if precaution.upper() == 'Y':
            change_master_pw(master_fp=master_fp, credentials_fp=credentials_fp, backup_fp=backup_fp)
            print("Successfully created new master password!")
        else:
            print("Returning to menu...")
            return
    else:
        print("Incorrect master password. Returning to menu...")
        return


def change_master_pw(master_fp: str, credentials_fp: str, backup_fp: str) -> None:
    # HELPER FUNCTION FOR menu_change_master_pw()
    # Handles the actual master password changing

    # Back up original credentials in a backup/ folder
    # Also back up the old master file
    backup_credentials_and_master(master_fp, credentials_fp, backup_fp=backup_fp)

   
   # Back up old master key for decrypting old creds. Delete old master key at end
    backup_old_master_key()

    # Create a new master password file
    # This will make the program use a new master key with the new master password
    create_master_pw(master_fp)

    # Decrypt and re-encrypt all old credentials using the new master password as key
    re_encrypt_creds_to_new_master_pw(master_fp)

    # Replace old master password and master key
    delete_master_pw(DEFAULT_OLD_MASTER_FP)
    delete_old_master_key()


def backup_credentials_and_master(master_fp: str, credentials_fp: str, backup_fp: str) -> None:
    # Create a new folder in backup/ only if backup folder doesn't exist already
    # Probably doesn't because we use seconds in the datetime frfr
    current_time = datetime.now().strftime('%B %d %Y %H-%M-%S')
    new_backup_fp = backup_fp + current_time + '\\'
    new_backup_credentials_fp = new_backup_fp + 'credentials\\'
    if not os.path.exists(new_backup_fp):
        # Create the parent backup folder
        os.makedirs(new_backup_fp)
        # Backup credentials folder structure from main folder:
        # ./backup/datetime/credentials
        copy_credentials_to_new_folder(credentials_fp, new_backup_credentials_fp)
        copy_master_to_backup_date_folder(master_fp, new_backup_fp)
        # Store old master in current folder for now. To be used in re-encryption
        backup_old_master(master_fp)

        print("Backed up credentials and master file to ", new_backup_fp, " successfully!")
        print("Copied old credential files from ", credentials_fp, ' to ', new_backup_credentials_fp)
    else:
        print(new_backup_fp, " exists already. Not overwriting directory.")


def backup_old_master_key() -> None:
    global old_master_key 
    old_master_key = master_key


def delete_old_master_key() -> None:
    global old_master_key


def backup_old_master(master_fp: str, old_master_fp: str=DEFAULT_OLD_MASTER_FP) -> None:
    if path.exists(old_master_fp):
        # Delete old master if it exists
        print("Duplicate old master file found. Deleting...")
        delete_master_pw(old_master_fp)
    shutil.copy(master_fp, old_master_fp)
    print("Successfully backed up old master file for re-encryption. Saved as ", old_master_fp)


def copy_credentials_to_new_folder(credentials_fp: str, new_folder_fp: str) -> None:
    # Create new folder
    os.makedirs(new_folder_fp)

    # Copy credentials files from credentials_fp and move them to the new folder fp
    credential_file_name_list = get_files_in_folder(credentials_fp)
    for file_name in credential_file_name_list:
        source_fp = credentials_fp + file_name
        destination_fp = new_folder_fp + file_name
        shutil.copy(source_fp, destination_fp)


def copy_master_to_backup_date_folder(master_fp: str, backup_fp: str) -> None:
    # Copy the master file into a backup folder
    destination_fp = backup_fp + 'master.txt'
    shutil.copy(master_fp, destination_fp)


def delete_master_pw(master_fp: str=DEFAULT_MASTER_FP):
    # Delete master password file
    try:
        os.remove(master_fp)
        print("Successfully removed master file: ", master_fp)
    except:
        print("Error: ", master_fp, " could not be deleted.")


def re_encrypt_creds_to_new_master_pw(new_master_fp: str=DEFAULT_MASTER_FP, old_master_fp: str=DEFAULT_OLD_MASTER_FP, credentials_folder_fp: str=DEFAULT_CREDENTIALS_FOLDER_FP) -> None:
    # For every credential in credentials, decrypt with old_master_fp
    for filename in get_files_in_folder(credentials_folder_fp):
        # Continue only if .json
        if filename[-5:] == '.json':
            credentials_file_fp = credentials_folder_fp + filename
            app_name = filename[0:-5]

            # Decrypt old credential files using old master key
            # Store in program temporarily
            credentials_dict = decrypt_credentials_file(credentials_file_fp, app_name, old_master_key)

            # Re-encrypting the new json should overwrite the old credential files
            # Encrypt into new files with same name
            encrypt_pw_to_json(credentials_dict, credentials_file_fp)


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


def display_end_program() -> None:
    print("Exiting PassMan 2.0... Good bye :)")
    time.sleep(1)
    clear_terminal(5)
    return


def clear_terminal(wait_sec: int) -> None:
    print("Clearing terminal in {sec} seconds for security's sake".format(sec=str(wait_sec)))
    for i in range(wait_sec, 0, -1):
        print(i)
        time.sleep(1)
    print('Clearing...')
    os.system('cls||clear')


def main():
    # Create a new master password if a master password already exists
    master_fp: str = DEFAULT_MASTER_FP
    if path.exists(master_fp):
        if not challenge_master_pw():
            return
    else:
        print("No master password file found.")
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
            menu_change_master_pw()
        elif option == "amogus":
            print("amogus jumpscare!!!!")
        elif option != "6":
            print(option , " is not a valid option. Enter a valid number from the menu below \n \/\/\/\/\/")
            display_menu(print_cool=False)
        option = input("Enter the number of the option you wish to perform: ")
    display_end_program()
        


if __name__ == "__main__":
    main()