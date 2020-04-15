# PassMan
A simple desktop password manager made with Python and Pycryptodome. Uses AES-128 for encrypting password, and PBKDF2 for creating the key using the master password. SHA3 is used to verify the master password.

### Functionality
Currently, PassMan can do the following (through the Python terminal):
* Create a master password
* Store credentials (username, password, site/application)
* Encrypt credentials using AES-128 (EAX)
* Retrieve credentials
* Delete credentials from storage
* Change master password
* Stores encrypted data in JSON files

### To-Do (in no particular order)
* Create a user interface

### Usage
To use the PassMan, create a master password that only you know. Then, follow the terminal prompts to store and retrieve credentials.
