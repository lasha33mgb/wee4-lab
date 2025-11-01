# Step 1: Created a message file for later encryption
with open("message.txt", "w") as file:
    file.write("This is my secret message for the SANGU Applied Cryptography course lab4.")
# Step 2: Generated RSA private and public keys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generated a 2048-bit RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Saved the private key to a file called private.pem
with open("private.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Created the public key from the private one
public_key = private_key.public_key()

# Saved the public key to a file called public.pem
with open("public.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
# Step 3: Encrypted the message using the public RSA key

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization  # Add serialization import here

# Loaded the public key from the file
with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Read the original message from the file
with open("message.txt", "rb") as f:
    message = f.read()

# Encrypted the message using RSA and OAEP padding
encrypted_message = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Saved the encrypted message to a file
with open("message_rsa_encrypted.bin", "wb") as f:
    f.write(encrypted_message)
# Step 4: Decrypt the message using the RSA private key

# Load the private key from the file
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Read the encrypted message from the file
with open("message_rsa_encrypted.bin", "rb") as f:
    encrypted_message = f.read()

# Decrypt the message
decrypted_message = private_key.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the decrypted message to a file
with open("message_rsa_decrypted.txt", "wb") as f:
    f.write(decrypted_message)
# Step 5: Encrypted the message using AES-256 (symmetric encryption)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

# Read the original message
with open("message.txt", "rb") as f:
    data = f.read()

# Pad the data to be compatible with AES block size (128 bits)
padder = sym_padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

# Generated a random 32-byte key (256 bits) and 16-byte IV (128 bits)
key = os.urandom(32)
iv = os.urandom(16)

# Saved the AES key and IV to files
with open("aes_key.bin", "wb") as f:
    f.write(key)
with open("aes_iv.bin", "wb") as f:
    f.write(iv)

# Encrypted the padded message using AES CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

# Save the encrypted data to a binary file
with open("message_aes_encrypted.bin", "wb") as f:
    f.write(ciphertext)
# Step 6: Decrypted the AES-encrypted message using the saved key and IV

# Loaded the AES key and IV from files
with open("aes_key.bin", "rb") as f:
    key = f.read()

with open("aes_iv.bin", "rb") as f:
    iv = f.read()

# Loaded the encrypted message
with open("message_aes_encrypted.bin", "rb") as f:
    encrypted_data = f.read()

# Created the AES cipher for decryption
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

# Removed the padding
unpadder = sym_padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

# Saved the decrypted message to a file
with open("message_aes_decrypted.txt", "wb") as f:
    f.write(decrypted_data)
# Step 7: Wrote a short explanation comparing RSA and AES

with open("rsa_vs_aes.txt", "w") as file:
    file.write(
        "RSA is an asymmetric encryption method that uses a public and private key. "
        "It is slower and usually is used for encrypting small amounts of data, like keys.\n"
        "AES is a symmetric encryption method that uses one secret key for both encryption and decryption. "
        "It is much faster and better for encrypting large files.\n"
        "In real-world systems, RSA is often used to securely share an AES key, and AES is then used to encrypt the actual message."
    )