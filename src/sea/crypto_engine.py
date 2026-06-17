import time
import os
from enum import Enum
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

try:
    from ascon import ascon_encrypt, ascon_decrypt
    HAS_ASCON = True
except ImportError:
    HAS_ASCON = False

try:
    import oqs
    HAS_OQS = True
except ImportError:
    HAS_OQS = False


class DeviceType(Enum):
    SENSOR = "sensor"
    CAMARA = "camara"
    CRITICO = "critico"


class SecurityLevel(Enum):
    BAJO = 1
    MEDIO = 2
    ALTO = 3
    CRITICO = 4


@dataclass
class Context:
    battery: float
    threat: bool
    device: DeviceType
    sensitivity: SecurityLevel


class CryptoEngine:
    def __init__(self):
        self.stats = {}
        self.aes_key = os.urandom(32)
        self.chacha_key = ChaCha20Poly1305.generate_key()
        self.ecc_private = ec.generate_private_key(ec.SECP256R1())
        if HAS_ASCON:
            self.ascon_key = os.urandom(16)
            self.ascon_nonce = os.urandom(16)
        if HAS_OQS:
            self.kyber_server = oqs.KeyEncapsulation("Kyber512")
            self.kyber_public = self.kyber_server.generate_keypair()

    def _encrypt_aes(self, data):
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + nonce + encryptor.tag

    def _encrypt_chacha(self, data):
        nonce = os.urandom(12)
        return ChaCha20Poly1305(self.chacha_key).encrypt(nonce, data, None)

    def _encrypt_ecc(self, data):
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        shared = ephemeral.exchange(ec.ECDH(), self.ecc_private.public_key())
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecc_aes")
        aes_key = hkdf.derive(shared)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + nonce + encryptor.tag

    def _encrypt_ascon(self, data):
        if HAS_ASCON:
            ciphertext, tag = ascon_encrypt(self.ascon_key, self.ascon_nonce, data, variant="Ascon-128")
            return ciphertext + tag
        return self._encrypt_aes(data)

    def _encrypt_kyber(self, data):
        if HAS_OQS:
            with oqs.KeyEncapsulation("Kyber512") as client:
                ciphertext, secret = client.encap_secret(self.kyber_public)
                nonce = os.urandom(12)
                cipher = Cipher(algorithms.AES(secret[:32]), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                ct = encryptor.update(data) + encryptor.finalize()
                return ciphertext + nonce + ct + encryptor.tag
        return self._encrypt_aes(data)

    def select_algorithm(self, context: Context) -> str:
        if context.threat and context.sensitivity == SecurityLevel.CRITICO:
            return "kyber" if HAS_OQS else "ecc"
        if context.battery < 0.25:
            return "ascon" if HAS_ASCON else "chacha"
        if context.device == DeviceType.SENSOR:
            return "chacha"
        return "aes"

    def encrypt(self, data: bytes, context: Context) -> Tuple[bytes, str, float]:
        algo = self.select_algorithm(context)
        start = time.perf_counter()
        if algo == "aes":
            result = self._encrypt_aes(data)
        elif algo == "chacha":
            result = self._encrypt_chacha(data)
        elif algo == "ecc":
            result = self._encrypt_ecc(data)
        elif algo == "ascon":
            result = self._encrypt_ascon(data)
        elif algo == "kyber":
            result = self._encrypt_kyber(data)
        else:
            result = self._encrypt_aes(data)
        elapsed = time.perf_counter() - start
        self.stats[algo] = self.stats.get(algo, 0) + 1
        return result, algo, elapsed


def run_demo():
    print("=" * 60)
    print("ARQUITECTURA SEA - DEMOSTRACION")
    print("=" * 60)
    engine = CryptoEngine()
    scenarios = [
        Context(0.85, False, DeviceType.CAMARA, SecurityLevel.MEDIO),
        Context(0.15, False, DeviceType.SENSOR, SecurityLevel.BAJO),
        Context(0.45, True, DeviceType.CRITICO, SecurityLevel.CRITICO),
        Context(0.70, False, DeviceType.SENSOR, SecurityLevel.BAJO),
    ]
    mensajes = [
        b"Datos de camara - flujo continuo",
        b"Lectura sensor - bateria critica",
        b"ALERTA: Datos criticos - amenaza",
        b"Telemetria sensor - operacion normal",
    ]
    for i, (context, msg) in enumerate(zip(scenarios, mensajes)):
        _, algo, elapsed = engine.encrypt(msg, context)
        print(f"Escenario {i + 1}: Bateria={context.battery * 100:.0f}% | Amenaza={context.threat}")
        print(f"   Algoritmo: {algo.upper()} | Tiempo: {elapsed * 1000:.2f} ms\n")
    print("ESTADISTICAS:")
    for algo, count in engine.stats.items():
        print(f"   {algo.upper()}: {count} veces")


if __name__ == "__main__":
    run_demo()
