import subprocess
import os
import logging
import importlib
import bcrypt
import mysql.connector as PyMySQL
from cryptography.fernet import Fernet


def check_and_install_modules():
    required_modules = ['cryptography','mysql-connector-python','bcrypt']
    for module in required_modules:
        try:
            importlib.import_module(module)
        except ImportError:
            subprocess.call(['pip', 'install', module])

def install_mysql():
    system = os.name
    if system == "nt":
        package_manager = "choco"
    else:
        package_manager = "brew"
    try:
        subprocess.run([package_manager, "--version"], check=True,capture_output=True)
    except:
        if package_manager == "choco":
            subprocess.run(["powershell", "-Command", "Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"], check=True, capture_output=True)
        elif package_manager == "brew":
            subprocess.run(["/bin/bash", "-c", "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"])
        else:
            raise ValueError("Package Manager Does Not Support")
    subprocess.run([package_manager, "install", "mysql"])


class PasswordManager:

    def __init__(self):
        self.host = "MYSQL_HOST"
        self.user = "MYSQL_USER"
        self.password = "MYSQL_PASSWORD"
        self.db = "MYSQL_DB"
        self.conn = None
        self.cursor = None
        self.logged_in = False
        self.username = None
        self.key = None
        self.fernet = None
        self.login_attempts = 0
        self.MAX_LOGIN_ATTEMPTS = 5
        self.known_plaintext = b"known_plaintext"
        self.known_ciphertext = None

    def check_and_connect(self):
        if self.host is None or self.user is None or self.password is None or self.db is None:
            raise ValueError("MySQL connection details are not properly set.")
        try:
            self.conn = PyMySQL.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                db=self.db
            )
            self.cursor = self.conn.cursor()
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                                (site text, password text)''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS users
                                (username text, password text)''')
            self.conn.commit()
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            raise ValueError("An error occurred while connecting to the MySQL server.")

    def create_user(self,username, password):
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            return
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            self.cursor.execute("INSERT INTO users (username,password) VALUES (%s,%s)",(username,hashed_password))
            self.conn.commit()
            print("User created successfully.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            print("An error occurred, please try again.")

    def user_login(self,username,password):
        self.cursor.execute("SELECT * FROM users WHERE username = %s",(username,))
        data = self.cursor.fetchone()
        if data is not None:
            db_password = data[1]
            if bcrypt.checkpw(password.encode(),db_password.encode()):
                self.logged_in = True
                self.username = username
                self.login_attempts = 0
                print("User logged in successfully.")
                return True
            else:
                print("Wrong Password.")
                self.login_attempts += 1
                if self.login_attempts >= self.MAX_LOGIN_ATTEMPTS:
                    print("Maximum login attempts reached, user is now locked out.")
                return False
        else:
            print("Username not found.")
            return False

    def create_key(self, path):
        if not self.logged_in:
            print("User must be logged in to create a key.")
            return
        self.key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(self.key)
            print(f"Key created at {path}")

    def load_key(self, path):
        if not self.logged_in:
            print("User must be logged in to load a key.")
            return
        try:
            with open (path, "rb") as f:
                self.key = f.read()
            print("Key Loaded Successfully.")
        except FileNotFoundError:
            print("The key file does not exist.")
            return

    def add_password(self, site, password):
        if not self.logged_in:
            print("User must be logged in to add a password.")
            return

        if self.key is None:
            print("A key must be loaded before adding a password.")
            return
        encrypted = Fernet(self.key).encrypt(password.encode())

        try:
            self.cursor.execute("INSERT INTO passwords (site,password) VALUES (%s,%s)",(site,encrypted))
            self.conn.commit()
            print("Password added successfully.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            print("An error occurred, please try again.")

    def get_password(self, site):
        if not self.logged_in:
            print("User must be logged in to retrieve a password.")
            return
        if self.key is None:
            print("A key must be loaded before retrieving a password.")
            return
        self.cursor.execute("SELECT password FROM passwords WHERE site = %s", (site,))
        data = self.cursor.fetchone()
        if data is not None:
            decrypted = Fernet(self.key).decrypt(data[0]).decode()
            print(f"Username: {self.username}\nPassword: {decrypted}")
        else:
            print(f"No password found for {site}.")

    def update_password(self, site, password):
        if not self.logged_in:
            print("User must be logged in to update a password.")
            return
        if self.key is None:
            print("Key must be loaded before adding a password.")
            return
        if not os.path.exists(self.key):
            print("Key file does not exist.")
            return
        self.fernet = Fernet(self.key)
        cipher_text = self.fernet.encrypt(password.encode())
        try:
            self.cursor.execute("UPDATE passwords SET password = %s WHERE site = %s AND username = %s", (cipher_text, site, self.username))
            self.conn.commit()
            print("Password updated successfully.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            print("An error occurred, please try again.")
    
    def list_passwords(self):
        if not self.logged_in:
            print("User must be logged in to list passwords.")
            return
        if self.key is None:
            print("A key must be loaded before listing passwords.")
            return
        self.cursor.execute("SELECT site, password FROM passwords")
        data = self.cursor.fetchall()
        if data:
            for site, password in data:
                decrypted = Fernet(self.key).decrypt(password).decode()
                print(f"{site}: {decrypted}")
        else:
            print("No passwords found.")

    def delete_password(self, site):
        if not self.logged_in:
            print("User must be logged in to delete a password.")
            return
        try:
            self.cursor.execute("DELETE FROM passwords WHERE site = %s AND username = %s", (site, self.username))
            self.conn.commit()
            print("Password deleted successfully.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            print("An error occurred, please try again.")
    
    def change_password(self, old_password, new_password):
        if not self.logged_in:
            print("User must be logged in to change password.")
            return
        if self.key is None:
            print("A key must be loaded before changing a password.")
            return
        self.cursor.execute("SELECT password FROM users WHERE username = %s", (self.username,))
        data = self.cursor.fetchone()
        if data is not None:
            db_password = data[0]
        if bcrypt.checkpw(old_password.encode(),db_password.encode()):
                hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                self.cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, self.username))
                self.conn.commit()
                print("Password changed successfully.")

    def check_key_integrity(self):
        if not self.logged_in:
            print("User must be logged in to check key integrity.")
            return
        if self.key is None:
            print("Key not found.")
            return
        if self.fernet is None:
            self.fernet = Fernet(self.key)
        ciphertext = self.fernet.encrypt(self.known_plaintext)
        if ciphertext == self.known_ciphertext:
            print("Key integrity check passed.")
        else:
            print("Key integrity check failed.")

    def logout(self):
        self.logged_in = False
        self.username = None
        self.key = None
        self.fernet = None
        self.login_attempts = 0
        print("User logged out successfully.")

    def close_connection(self):
        self.cursor.close()
        self.conn.close()
        print("Database connection closed.")

def main():
    check_and_install_modules()
    pm = PasswordManager()
    pm.check_and_connect()

    while True:
        print("1. Create User")
        print("2. Login")
        print("3. Create Key")
        print("4. Load Key")
        print("5. Add Password")
        print("6. Update Password")
        print("7. Delete Password")
        print("8. Change Password")
        print("9. Logout")
        print("10. Exit")
        choice = int(input("Enter your choice: "))

        if choice == 1:
            username = input("Enter a username: ")
            password = input("Enter a password: ")
            pm.create_user(username, password)
        elif choice == 2:
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            pm.user_login(username, password)

        elif choice == 3:
            path = input("Enter the path to save the key file: ")
            pm.create_key(path)
        elif choice == 4:
            path = input("Enter the path to the key file: ")
            pm.load_key(path)

        elif choice == 5:
            if pm.key is None:
                print("A key must be loaded before adding a password.")
                continue
            site = input("Enter the site name: ")
            password = input("Enter the password: ")
            pm.add_password(site, password)
        elif choice == 6:
            if pm.key is None:
                print("A key must be loaded before updating a password.")
                continue
            site = input("Enter the site name: ")
            password = input("Enter the new password: ")
            pm.update_password(site, password)
        elif choice == 7:
            if pm.key is None:
                print("A key must be loaded before deleting a password.")
                continue
            site = input("Enter the site name: ")
            pm.delete_password(site)
        elif choice == 8:
            if pm.key is None:
                print("A key must be loaded before updating a password.")
                continue
            password = input("Enter the new password: ")
            pm.change_password(password)
        elif choice == 9:
            pm.logout()
        elif choice == 10:
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
