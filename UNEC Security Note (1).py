import os
from cryptography.fernet import Fernet
import hashlib
import maskpass
import re

class Login_Error(Exception):
    pass


class User_password_base:
    def __init__(self, username, password):
        self.username = username.strip()
        self.password = password.strip()

        user_dir = os.path.join("users", self.username)
        os.makedirs(user_dir, exist_ok=True)

        with open("Users_names.txt", "a+") as f: 
            f.write(self.username + ",")
        with open("Users_password.txt", "a+") as fi:
            self.password = hashlib.sha256(self.password.encode()).hexdigest()
            fi.write(self.password + ",")
        with open("The_keys.txt","a+") as fi:
            key=Fernet.generate_key().decode()
            fi.write(key+",")


class Plain_Note:
    def __init__(self,content,username):
        self.content=content
        self.username=username
    def show_pn(self):
        return self.content 


def rtrn_key(username):
    with open('Users_names.txt', 'a+') as file:
        file.seek(0)
        users = file.read().split(',')
    with open("The_keys.txt","a+") as f:
        f.seek(0)
        keys=f.read().split(",")

    key= keys[users.index(username)]
    return key



class Encrypted_Note(Plain_Note):
    def __init__(self, content, username):
        super().__init__(content,username)          
        self.username = username            
        self.key = rtrn_key(username)        
        self.f = Fernet(self.key.encode())   

    def encrypt(self):
        return self.f.encrypt(self.content.encode()).decode()

    def decrypt(self):
        return self.f.decrypt(self.content.encode()).decode()


def Check_User_paswd(us):
    with open("Users_names.txt", "a+") as fi:
        fi.seek(0)
        users = fi.read().split(",")
    if us in users:
        return False
    return True

def check_user(username, password):
    with open('Users_names.txt', 'a+') as file:
        file.seek(0)
        users = file.read().split(',')
    with open("Users_password.txt", "a+") as f:
        f.seek(0)
        passwords = f.read().split(",")
    if username in users:
        index = users.index(username)
        if passwords[index] == hashlib.sha256(password.encode()).hexdigest():
            return True
        return False
    return False


def login_user(username):
    user_dir = os.path.join("users", username)
    print(f"Welcome, {username}!")
    while True:
        print("Please choose an option:")
        print("------------------------")
        print("1.create plaintext")
        print("2.view text list")
        print("3.Delete text")
        print("4.logout")
        choice = input("Enter your choice: ")
        if choice == "1":
            print("-----------------------")
            plaintext_name = input("Enter your plaintext name: ")
            file_path = os.path.join(user_dir, plaintext_name + ".txt")
            if not os.path.exists(file_path):
                with open(file_path, "w+") as pt:
                    print("-----------------------")
                    text = input("Enter your plaintext content: ")
                    pt.write(Encrypted_Note(text,username).encrypt())
                    print("-----------------------")
                    print("Your plaintext has been created successfully")
                    print("-----------------------")
            else:
                print("----------------------")
                print("A plaintext with this name already exists. Please choose another name.")
                print("----------------------")
                continue
        elif choice == "2":
            files = os.listdir(user_dir)
            print("-----------------------")
            print("Your text files are:")
            for file in files:
                if file.endswith(".txt"):
                    print(file)
            print("-----------------------")
            print("1.Open a file to view its plain content")
            print("2.Back to menu")
            sub_choice = input("Enter your choice (1 or 2): ")
            if sub_choice == "1":
                file_to_open = input("Enter the filename (with .txt extension): ")
                file_path = os.path.join(user_dir, file_to_open)
                if os.path.exists(file_path):
                    for i in range (5):
                        check_pswd=maskpass.askpass("Enter password for decrypted text view:",mask="*")
                        if check_user(username, check_pswd):
                            with open(file_path, "r") as fi:
                                fi.seek(0)
                                content = Encrypted_Note(fi.read(),username).decrypt()
                                print("-----------------------")
                                print("Content of", file_to_open + ":",end="")
                                print(content+"\n")
                                break
                        else:
                            print("-----------------------")
                            print(f"Invalid password.You have {5-i-1} chance to")
                    else:
                        print("-----------------------")
                        print("Too many failed login attempts!")
                        continue


            elif sub_choice == "2":
                print("backing to menu ...")
                print("-----------------------")
                continue
        elif choice == "3":
            print("-----------------------")
            file_to_delete = input("Enter the filename to delete (with .txt extension): ")
            file_path = os.path.join(user_dir, file_to_delete)
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"{file_to_delete} has been deleted successfully.")
                print("-----------------------")
            else:
                print("The specified file does not exist.")
                print("-----------------------")
        elif choice == "4":
            print("-----------------------")
            print("Logging out ...")
            break

print("Welcome to the UNEC Secure Note System")
while True:
    
    print("-----------------------")
    print("1.Register")
    print("2.Login")
    print("3.Remove Account")
    print("4.Exit")
    print("-----------------------")
    choice = input("Enter your choice (1 or 2 or 3 or 4): ")
    if choice == '1':
        try:
            print("Register a new account")
            print("-----------------------")
            username = input("Enter a username to register: ")
            print("Password requirements:")
            print("1. At least 8 characters long")
            print("2. Contains at least one uppercase letter")
            print("3. Contains at least one lowercase letter")
            print("4. Contains at least one digit")
            print("5. Contains at least one special character from @ $ ! % * ? &")
            choice1=input("Do you want to see the password ? (y/n): ").strip().lower()
            if choice1 == "y":
                password=input("Enter a password to register: ")
            elif choice1 == "n":        
                password = maskpass.askpass("Enter a password to register: ",mask="*")
            else:
                raise Login_Error("Invalid choice. Please enter 'y' or 'n'")
            if  re.fullmatch(r"[a-zA-Z\d@_#&]{1,}",username):
                if re.fullmatch(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",password):
                    if Check_User_paswd(username):
                       User_password_base(username, password)
                       print("-----------------------")
                       print("You registered successfully! \nYou can login now")
                       continue
                    else:
                        raise Login_Error("Your username has already been claimed")
                else:
                    raise Login_Error("Password is invalid. It must be strong ")
            else:
                raise Login_Error("Username is Invalid")
        except Login_Error as e:
            print(e)
    elif choice == '2':
        try:
            print("Login to your account")
            username = input("Enter a username to Login: ")
            password = maskpass.askpass("Enter a password to Login: ",mask="*")
            if  re.fullmatch(r"[a-zA-Z\d@_#&]{1,}",username):
                if re.fullmatch(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",password):
                    if check_user(username, password):
                        print("Your login is successful")
                        print("-----------------------")
                        login_user(username)
                    else:
                        raise Login_Error("Invalid username or password.")
                else:
                    raise Login_Error("Password is invalid.Please try again.")
            else:
                raise Login_Error("Username is Invalid")
        except Login_Error as e:
            print(e)
    elif choice == "3":
        print("-----------------------")
        print("Remove your account")
        username = input("Enter your username: ")
        password = maskpass.askpass("Enter your password: ",mask="*")
        if check_user(username, password):
            with open('Users_names.txt', 'r+') as file:
                users = file.read().split(',')
                if username in users:
                    index = users.index(username)
                    users.pop(index)
                    file.seek(0)
                    file.truncate()
                    file.write(','.join(users))
            with open("Users_password.txt", "r+") as f:
                passwords = f.read().split(",")
                passwords.pop(index)
                f.seek(0)
                f.truncate()
                f.write(','.join(passwords))
            with open("The_keys.txt","r+") as fi:
                keys=fi.read().split(",")
                keys.pop(index)
                fi.seek(0)
                fi.truncate()
                fi.write(','.join(keys))
            user_dir = os.path.join("users", username)
            if os.path.exists(user_dir):
                for filename in os.listdir(user_dir):
                    file_path = os.path.join(user_dir, filename)
                    os.remove(file_path)
                os.rmdir(user_dir)
            print("Your account has been removed successfully.")
            print("-----------------------")
    elif choice == "4":
        print("-----------------------")
        print("System is closing ...")
        break
    else:
        print("This command doesn't exist. Please choose between 1 or 2 or 3 or 4")