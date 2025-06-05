from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

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
    """Encrypt a message using a public RSA key."""
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


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
