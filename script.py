from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import os

def get_key_from_password(password, salt):
    """
    Derives a secret key from the password and salt.
    """
    # Using PBKDF2HMAC as the key derivation function
    kdf = PBKDF2HMAC( 
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    # derives a key from the password and salt
    key = urlsafe_b64encode(kdf.derive(password.encode())) 

    return key


def encrypt_file(filename, password):
    """
    Encrypts the file with the key derived from the password.
    Writes the salt used for key derivation at the start of the encrypted file.
    """
    # Generate a random salt
    salt = os.urandom(16)
    # Derive a key from the password and salt
    key = get_key_from_password(password, salt)

    f = Fernet(key) # Create a Fernet object with the key

    # Read the file data
    with open(filename, "rb") as file:
        file_data = file.read()
    # Encrypt the file data
    encrypted_data = f.encrypt(file_data)
    # Write the encrypted file data
    with open(filename, "wb") as file:
        file.write(salt + encrypted_data)


def decrypt_file(filename, password):
    """
    Decrypts the file using the key derived from the password.
    Reads the salt from the start of the encrypted file.
    """
    # Read the file data
    with open(filename, "rb") as file:
        file_data = file.read()
    # Extract the salt and encrypted file data
    salt, encrypted_data = file_data[:16], file_data[16:]
    # Derive the key from password and salt
    key = get_key_from_password(password, salt)

    f = Fernet(key) # Create a Fernet object with the key
    # Decrypt the file data
    decrypted_data = f.decrypt(encrypted_data)
    # Write the decrypted file data
    with open(filename, "wb") as file:
        file.write(decrypted_data)


def encrypt_folder(folder_name, password):
    """
    Encrypts all the files in the specified folder.
    """
    # Iterate over all the files in the folder
    for filename in os.listdir(folder_name):
        # Get the path of the file
        filepath = os.path.join(folder_name, filename)
        # If we are dealing with a file
        if os.path.isfile(filepath):  
            encrypt_file(filepath, password)
            print(f"{filename} has been encrypted!")
        # If we are dealing with a sub-folder
        else:
            # Recursively call the same function
            encrypt_folder(filepath, password)


def decrypt_folder(folder_name, password):
    """
    Decrypts all the files in the specified folder.
    """
    # Iterate over all the files in the folder
    for filename in os.listdir(folder_name):
        # Get the path of the file
        filepath = os.path.join(folder_name, filename)
        # If we are dealing with a file
        if os.path.isfile(filepath):  
            decrypt_file(filepath, password)
            print(f"{filename} has been decrypted!")
        # If we are dealing with a sub-folder
        else:
            # Recursively call the same function
            decrypt_folder(filepath, password)

# The salt used for key derivation
def operate_on_folder():
    """
    Encrypts or decrypts all the files in the specified folder.
    """
    # Get the folder path, password and choice
    folder_name = input("Enter the folder path: ")
    password = input("Enter your password: ")
    choice = input("Do you want to (E)ncrypt or (D)ecrypt?: ").upper()

    if choice == 'E':
        encrypt_folder(folder_name, password)
        print(f"All files in {folder_name} have been encrypted!")
    elif choice == 'D':
        decrypt_folder(folder_name, password)
        print(f"All files in {folder_name} have been decrypted!")
    else:
        print("Invalid choice!")

def opeate_on_file():
    """
    Encrypts or decrypts the specified file.
    """
    # Get the file path, password and choice
    filename = input("Enter the filename: ")
    password = input("Enter your password: ")
    choice = input("Do you want to (E)ncrypt or (D)ecrypt?: ").upper()

    if choice == 'E':
        encrypt_file(filename, password)
        print(f"{filename} has been encrypted!")
    elif choice == 'D':
        decrypt_file(filename, password)
        print(f"{filename} has been decrypted!")
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    """
    The main function.
    """
    # Get the choice
    choice = input("Do you want to operate on a (F)older or a (S)ingle file?: ").upper()
    # Call the appropriate function
    if choice == 'F':
        operate_on_folder()
    elif choice == 'S':
        opeate_on_file()
    else:
        print("Invalid choice!")