from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def demo_ecc():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    receiver_private = ec.generate_private_key(ec.SECP256R1())
    receiver_public = receiver_private.public_key()

    shared_secret = private_key.exchange(ec.ECDH(), receiver_public)

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecc_key")
    aes_key = hkdf.derive(shared_secret)

    nonce = os.urandom(12)
    mensaje = b"Mensaje cifrado con ECC + AES"

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(mensaje) + encryptor.finalize()

    print("=== ECC (P-256) + AES-GCM ===")
    print(f"Mensaje: {mensaje}")
    print(f"Cifrado: {ciphertext.hex()[:32]}...")
    return ciphertext


if __name__ == "__main__":
    demo_ecc()
