import oqs


def demo_kyber():
    kemalg = "Kyber512"
    with oqs.KeyEncapsulation(kemalg) as client:
        with oqs.KeyEncapsulation(kemalg) as server:
            public_key = server.generate_keypair()

            ciphertext, shared_secret_client = client.encap_secret(public_key)
            shared_secret_server = server.decap_secret(ciphertext)

            print("=== Kyber-512 (Post-Cuantico) ===")
            print(f"Clave publica: {public_key.hex()[:32]}...")
            print(f"Secreto compartido: {shared_secret_client.hex()[:16]}...")
            print(f"Exito: {shared_secret_client == shared_secret_server}")
            return shared_secret_client


if __name__ == "__main__":
    demo_kyber()
