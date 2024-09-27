# HybridCryptography
Enhancing Security Through Hybrid Cryptography: A Fusion of AES and RSA for Robust Encryption. 
Working Process 
In the encryption phase, plaintext data is encrypted using AES with the AES key, and the AES key itself is encrypted using RSA with the recipient's public key to ensure secure key exchange. In the decryption phase, the encrypted AES key is decrypted using RSA with the recipient's private key, and the ciphertext is decrypted using AES with the decrypted AES key.
