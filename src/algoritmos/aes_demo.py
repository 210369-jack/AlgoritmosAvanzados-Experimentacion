from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def demo_aes_gcm():
    key = os.urandom(32)
    nonce = os.urandom(12)
    mensaje = b"Mensaje cifrado con AES-256-GCM"

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(mensaje) + encryptor.finalize()
    tag = encryptor.tag

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    print("=== AES-256-GCM ===")
    print(f"Mensaje: {mensaje}")
    print(f"Descifrado: {plaintext}")
    return ciphertext


if __name__ == "__main__":
    demo_aes_gcm()
