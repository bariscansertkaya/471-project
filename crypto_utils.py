from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets

KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "privkey.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "pubkey.pem")


def generate_key_pair():
    """Generate RSA 2048-bit key pair and save to disk."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    os.makedirs(KEY_DIR, exist_ok=True)

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key


def load_keys():
    """Load RSA key pair from disk."""
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key


def encrypt_message(public_key, message: str) -> bytes:
    """
    Encrypt a message using a public RSA key.
    Raises ValueError if message is too large for RSA encryption.
    """
    message_bytes = message.encode('utf-8')
    
    # RSA 2048 with OAEP padding can encrypt at most 190 bytes
    # We use 180 as a safe limit to account for padding overhead
    max_rsa_size = 180
    
    if len(message_bytes) > max_rsa_size:
        raise ValueError(f"Message too large for RSA encryption: {len(message_bytes)} bytes > {max_rsa_size} byte limit. Use hybrid encryption instead.")
    
    try:
        return public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA encryption failed: {e}")


def decrypt_message(private_key, ciphertext: bytes) -> str:
    """Decrypt a message using a private RSA key."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return secrets.token_bytes(32)


def encrypt_large_message(public_key, message: str) -> tuple[bytes, bytes]:
    """
    Encrypt a large message using hybrid encryption (AES + RSA).
    Returns: (encrypted_aes_key, encrypted_data)
    """
    # Generate random AES key
    aes_key = generate_aes_key()
    
    # Generate random IV for AES
    iv = secrets.token_bytes(16)
    
    # Encrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad message to be multiple of 16 bytes (AES block size)
    message_bytes = message.encode('utf-8')
    padding_length = 16 - (len(message_bytes) % 16)
    padded_message = message_bytes + bytes([padding_length] * padding_length)
    
    encrypted_data = iv + encryptor.update(padded_message) + encryptor.finalize()
    
    # Encrypt the AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_aes_key, encrypted_data


def decrypt_large_message(private_key, encrypted_aes_key: bytes, encrypted_data: bytes) -> str:
    """
    Decrypt a large message using hybrid encryption (AES + RSA).
    """
    # Decrypt the AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Extract IV and encrypted message
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    padding_length = padded_message[-1]
    message = padded_message[:-padding_length]
    
    return message.decode('utf-8')


def export_public_key_base64(public_key) -> str:
    """Export a public key's DER format as a base64-encoded string."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


def import_public_key_base64(b64_string: str):
    """Import a public key from a base64-encoded DER string."""
    der = base64.b64decode(b64_string.encode())
    return serialization.load_der_public_key(der)
