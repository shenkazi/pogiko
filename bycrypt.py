import bcrypt
import time

RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify if the provided password matches the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def print_ascii_banner():
    banner = """
		 ▄████▄    ██████  ██░ ██ 
		▒██▀ ▀█  ▒██    ▒ ▓██░ ██▒
		▒▓█    ▄ ░ ▓██▄   ▒██▀▀██░
		▒▓▓▄ ▄██▒  ▒   ██▒░▓█ ░██ 
		▒ ▓███▀ ░▒██████▒▒░▓█▒░██▓
		░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒
		  ░  ▒   ░ ░▒  ░ ░ ▒ ░▒░ ░
		░        ░  ░  ░   ░  ░░ ░
		░ ░            ░   ░  ░  ░
		░                         
				Bcrypt DECODER!       
				-ST4LK3R
    """
    print(banner)

def check_passwords_from_file(hash_file: str, password_file: str, delay: float):
    """Read passwords from a file and check each one against the hash with a delay."""

    with open(hash_file, 'r') as file:
        stored_hash = file.read().strip()
    
    with open(password_file, 'r') as file:
        for line in file:
            password_to_check = line.strip()
            if verify_password(stored_hash, password_to_check):
                print(f"{GREEN}[FOUND!] {password_to_check}{RESET}")
                return  
            
            print(f"{RED}[NOT FOUND!] {password_to_check}{RESET}")
            time.sleep(delay)

    print(f"{RED}No matching password found.{RESET}")

if __name__ == "__main__":
    print_ascii_banner()  
    hash_file = 'hash.txt'
    password_file = 'password.txt'
    delay = 0.5

    check_passwords_from_file(hash_file, password_file, delay)
