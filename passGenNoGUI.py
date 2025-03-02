import random
import string
import hashlib
import base64
# from Crypto.Cipher import AES
from cryptography.fernet import Fernet

# Function to generate random password
def generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols):
    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return "Error: Please select at least one character type."

    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Function to calculate password strength
def calculate_strength(password):
    # A simple implementation to calculate password strength
    length = len(password)
    uppercase = sum(1 for c in password if c.isupper())
    lowercase = sum(1 for c in password if c.islower())
    numbers = sum(1 for c in password if c.isdigit())
    symbols = sum(1 for c in password if c in string.punctuation)

    strength = length * 4
    strength += (length - uppercase) * 2
    strength += (length - lowercase) * 2
    strength += numbers * 4
    strength += symbols * 6

    return min(strength, 100)

# Function to save passwords to file
def save_to_file(passwords):
    with open('generated_passwords.txt', 'a') as file:
        for password in passwords:
            file.write(password + '\n')

# Function to encrypt password
def encrypt_password(password, encryption_type):
    if encryption_type == 'sha512':
        hashed_password = hashlib.sha512(password.encode()).hexdigest()
        return hashed_password
    elif encryption_type == 'aes':
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_password = cipher.encrypt(password.encode()).decode()
        return encrypted_password, key.decode()
    elif encryption_type == 'base64':
        return base64.b64encode(password.encode()).decode(), None
    elif encryption_type == 'vigenere':
        key = 'KEY'
        encrypted_chars = []
        for i, char in enumerate(password):
            key_c = key[i % len(key)]
            encrypted_char = chr((ord(char) + ord(key_c)) % 256)
            encrypted_chars.append(encrypted_char)
        return ''.join(encrypted_chars), None
    else:
        return "Error: Invalid encryption type.", None

# Main function
def main():
    try:
        count = int(input("Enter the number of passwords to generate: "))
        length = int(input("Enter the length of passwords: "))
        use_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
        use_lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
        use_numbers = input("Include numbers? (y/n): ").lower() == 'y'
        use_symbols = input("Include symbols? (y/n): ").lower() == 'y'

        passwords = []
        for _ in range(count):
            password = generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols)
            passwords.append(password)

        for i, password in enumerate(passwords, start=1):
            print(f"Password {i}: {password}")
            print(f"Strength: {calculate_strength(password)}%")

            encryption_types = ['sha512', 'aes', 'base64', 'vigenere']
            encryption_option = input("Enter the type of encryption (sha512, aes, base64, vigenere), or 'none' to skip: ")
            if encryption_option.lower() != 'none':
                if encryption_option.lower() in encryption_types:
                    encrypted_password, key = encrypt_password(password, encryption_option.lower())
                    print(f"Encrypted Password: {encrypted_password}")
                    if key:
                        print(f"Key: {key}")
                else:
                    print("Invalid encryption type.")
            else:
                print("Encryption skipped.")

        save_option = input("Do you want to save these passwords to file? (y/n): ").lower()
        if save_option == 'y':
            save_to_file(passwords)

    except ValueError:
        print("Error: Please enter a valid number.")

if __name__ == "__main__":
    main()
