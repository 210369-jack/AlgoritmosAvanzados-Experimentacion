from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os


def demo_chacha():
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    mensaje = b"Mensaje cifrado con ChaCha20-Poly1305"

    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, mensaje, None)
    plaintext = cipher.decrypt(nonce, ciphertext, None)

    print("=== ChaCha20-Poly1305 ===")
    print(f"Mensaje: {mensaje}")
    print(f"Descifrado: {plaintext}")
    return ciphertext


if __name__ == "__main__":
    demo_chacha()
