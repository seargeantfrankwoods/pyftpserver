import os
import sqlite3
import bcrypt
import configparser
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_config(filename): # Loads .ini files for settings
    config = configparser.ConfigParser()
    if os.path.exists(filename):
        config.read(filename)
        return config
    else:
        return None
    
def is_valid_config(config): #Check if config.ini is valid
    # Check if TLS, anonymous login, and user authentication settings are valid
    if not config.get('FTP', 'tls_enabled').isdigit() or not config.get('FTP', 'anonymous_login_enabled').isdigit() or not config.get('FTP', 'user_authentication_enabled').isdigit():
        return False
    return True

def config_setup_wizard(): #If config.ini is invalid, runs a setup wizard
    print("Welcome to the FTP server setup wizard!")
    config = configparser.ConfigParser()
    
    # Get server settings from user input
    config['FTP'] = {}
    config['FTP']['tls_enabled'] = input("Enable FTP over TLS? (0 for disabled, 1 for enabled): ")
    config['FTP']['anonymous_login_enabled'] = input("Enable anonymous login? (0 for disabled, 1 for enabled): ")
    config['FTP']['user_authentication_enabled'] = input("Enable user authentication? (0 for disabled, 1 for enabled): ")
    
    # Save configuration to config.ini file
    with open('config.ini', 'w') as configfile:
        config.write(configfile)
    
    return config

def is_valid_ports_config(ports_config):
    # Check if port settings are valid
    try:
        ports_config.getint('ListeningPort', 'listening_port')
        ports_config.getint('PassivePorts', 'passive_port_start')
        ports_config.getint('PassivePorts', 'passive_port_end')
        return True
    except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
        return False

def port_setup_wizard(): #If config.ini is invalid, runs a setup wizard
    print("Welcome to the FTP server setup wizard!")
    config = configparser.ConfigParser()
    
    # Get server settings from user input
    config['PassivePorts'] = {}
    config['PassivePorts']['passive_port_start'] = input("Set the starting passive port: ")
    config['PassivePorts']['passive_port_end'] = input("Set the ending passive port: ")
    config['ListeningPort'] = {}
    config['ListeningPort']['listening_port'] = input("Set the listening port: ")

    # Save configuration to config.ini file
    with open('ports.ini', 'w') as configfile:
        config.write(configfile)
    
    return config

def create_authorizer(config): #Validates users privileges
    authorizer = DummyAuthorizer()
    
    if config.getboolean('FTP', 'anonymous_login_enabled'):
        authorizer.add_anonymous("/home/admin/server")
        
    if config.getboolean('FTP', 'user_authentication_enabled'):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (user TEXT PRIMARY KEY, password TEXT, directory TEXT)")
        c.execute("SELECT user, password, directory FROM users")
        users = c.fetchall()
        if not users:
            print("No users found in users.db. Please add at least one user.")
            return None
        for user_row in users:
            username, password_hash, user_directory = user_row
            # Decrypt password using .pem keypair
            decrypted_password = decrypt_password(password_hash)
            # Add user with decrypted password and specified directory
            authorizer.add_user(username, decrypted_password, homedir=user_directory, perm='elradfmw' if username == "abstr4ck" else 'elradfm')
        conn.close()
            
    return authorizer

def decrypt_password(encrypted_password): #Decrypts user password
    # Load private key
    private_key = serialization.load_pem_private_key(
        # Replace 'private_key.pem' with your private key file path
        open('private_key.pem', 'rb').read(),
        password=None,
        backend=default_backend()
    )
    # Decrypt password
    decrypted_password = private_key.decrypt(
        encrypted_password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_password.decode()
    
def main(): #Main function
    config = load_config('config.ini')
    ports_config = load_config('ports.ini')

    if config is None or not is_valid_config(config):
        config = config_setup_wizard()

    if ports_config is None or not is_valid_ports_config(ports_config):
        config = port_setup_wizard()

    authorizer = create_authorizer(config)
    if not authorizer:
        return

    start_ftp_server(authorizer, config, ports_config)

def start_ftp_server(authorizer, config, ports_config): #Initiates the FTP server
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(ports_config.getint('PassivePorts', 'passive_port_start'), ports_config.getint('PassivePorts', 'passive_port_end')+1)
    handler.masquerade_address = '0.0.0.0'
    if config.getboolean('FTP', 'tls_enabled'):
        handler.tls_control_required = True
    server = FTPServer(("0.0.0.0", ports_config.getint('ListeningPort', 'listening_port')), handler)
    server.log = open('server.log', 'a')
    server.max_cons = 256
    server.max_cons_per_ip = 5
    server.serve_forever()

if __name__ == "__main__":
    main()

