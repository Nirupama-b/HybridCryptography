from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import time

# Padding functions for AES
def pad(s):
    pad_length = AES.block_size - len(s) % AES.block_size
    padding = bytes([pad_length]) * pad_length
    return s + padding

def unpad(s):
    pad_length = s[-1]
    return s[:-pad_length]

# Function to encrypt using AES
def encrypt_aes(plaintext_bytes, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = pad(plaintext_bytes)
    ciphertext = cipher.encrypt(plaintext)
    return base64.b64encode(ciphertext)

# Function to decrypt using AES
def decrypt_aes(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted)

# Function to encrypt using RSA
def encrypt_rsa(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted = cipher_rsa.encrypt(data)
    return base64.b64encode(encrypted)

# Function to decrypt using RSA
def decrypt_rsa(encrypted_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted = cipher_rsa.decrypt(base64.b64decode(encrypted_data))
    return decrypted

# Generate AES key
aes_key = get_random_bytes(16)  # AES key size is 16 bytes for AES-128

# Generate RSA key pair
rsa_key = RSA.generate(2048)

# Sample text
plaintext = "AES (Advanced Encryption Standard) stands as a cornerstone of modern cryptography, offering robust security and efficient performance in data encryption. Established by the National Institute of Standards and Technology (NIST) in 2001, AES replaced the aging Data Encryption Standard (DES) with a significantly enhanced algorithm. AES operates as a symmetric-key block cipher, supporting key sizes of 128, 192, or 256 bits. Its strength lies in its ability to securely encrypt data in fixed-size blocks, typically 128 bits, using a series of substitution and permutation operations known as rounds."

# Convert plaintext to bytes
plaintext_bytes = plaintext.encode()

# Start measuring execution time
start_time = time.time()

# Encrypt using AES
aes_encrypted = encrypt_aes(plaintext_bytes, aes_key)

# Encrypt AES key using RSA
rsa_encrypted_aes_key = encrypt_rsa(aes_key, rsa_key.publickey())

# Decrypt AES key using RSA
decrypted_aes_key = decrypt_rsa(rsa_encrypted_aes_key, rsa_key)

# Decrypt using AES with decrypted AES key
aes_decrypted = decrypt_aes(aes_encrypted, decrypted_aes_key)

# Stop measuring execution time
end_time = time.time()

print("Original message:", plaintext)
print("\nAES encrypted:", aes_encrypted)
print("\nRSA encrypted AES key:", rsa_encrypted_aes_key)
print("\nDecrypted AES key:", decrypted_aes_key)
print("\nDecrypted using AES with decrypted AES key:", aes_decrypted.decode())

# Calculate and print execution time
print("Execution time:", end_time - start_time, "seconds")
