from ascon import ascon_encrypt, ascon_decrypt
import os


def demo_ascon():
    key = os.urandom(16)
    nonce = os.urandom(16)
    mensaje = b"Hola Smart City desde ASCON!"

    ciphertext, tag = ascon_encrypt(key, nonce, mensaje, variant="Ascon-128")
    plaintext = ascon_decrypt(key, nonce, ciphertext, tag, variant="Ascon-128")

    print("=== ASCON-128 ===")
    print(f"Mensaje: {mensaje}")
    print(f"Cifrado: {ciphertext.hex()[:32]}...")
    print(f"Descifrado: {plaintext}")
    print(f"Exito: {mensaje == plaintext}")
    return ciphertext


if __name__ == "__main__":
    demo_ascon()
