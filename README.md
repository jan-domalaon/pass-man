# PassMan
A simple desktop password manager made with Python and Pycryptodome. Uses AES-128 for encrypting password, and PBKDF2 for creating the key using the master password. SHA3 is used to verify the master password.

### Functionality
Currently, PassMan can do the following (through the Python terminal):
* Create a master password
* Store credentials (username, password, site/application)
* Encrypt credentials using AES-128
* Retrieve credentials
* Delete credentials from storage
* Change master password

### To-Do (in no particular order)
* Create a user interface
* Store credentials in JSON format