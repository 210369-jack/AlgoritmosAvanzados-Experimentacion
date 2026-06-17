import csv
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src", "sea"))

from crypto_engine import CryptoEngine, Context, DeviceType, SecurityLevel


CONSUMO_RELATIVO = {
    "aes": 0.50,
    "chacha": 0.30,
    "ecc": 0.40,
    "kyber": 0.65,
    "ascon": 0.15,
}

TIEMPO_REFERENCIA = {
    "aes": 0.85,
    "chacha": 0.62,
    "ecc": 2.34,
    "kyber": 3.12,
    "ascon": 0.45,
}

ESCENARIOS = [
    ("Operacion Normal", Context(0.85, False, DeviceType.CAMARA, SecurityLevel.MEDIO),
     b"Datos de camara - flujo continuo"),
    ("Bateria Critica", Context(0.15, False, DeviceType.SENSOR, SecurityLevel.BAJO),
     b"Lectura sensor - bateria critica"),
    ("Amenaza Detectada", Context(0.45, True, DeviceType.CRITICO, SecurityLevel.CRITICO),
     b"ALERTA: Datos criticos - amenaza"),
    ("Alto Volumen", Context(0.70, False, DeviceType.SENSOR, SecurityLevel.BAJO),
     b"Telemetria sensor - operacion normal"),
]


def ejecutar_experimentos():
    engine = CryptoEngine()
    filas = []
    for nombre, context, mensaje in ESCENARIOS:
        _, algo, elapsed = engine.encrypt(mensaje, context)
        consumo_sea = CONSUMO_RELATIVO.get(algo, 0.50)
        ahorro = (1.0 - consumo_sea) * 100
        filas.append({
            "escenario": nombre,
            "algoritmo": algo.upper(),
            "consumo_tradicional": 1.00,
            "consumo_sea": consumo_sea,
            "ahorro_porcentaje": round(ahorro, 1),
            "tiempo_medido_ms": round(elapsed * 1000, 4),
            "tiempo_referencia_ms": TIEMPO_REFERENCIA.get(algo, 0.85),
        })
    return filas


def guardar_csv(filas, ruta):
    campos = ["escenario", "algoritmo", "consumo_tradicional", "consumo_sea",
              "ahorro_porcentaje", "tiempo_medido_ms", "tiempo_referencia_ms"]
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        writer.writerows(filas)


def main():
    filas = ejecutar_experimentos()
    salida = os.path.join(os.path.dirname(__file__), "..", "datos", "resultados.csv")
    os.makedirs(os.path.dirname(salida), exist_ok=True)
    guardar_csv(filas, salida)

    print("=" * 60)
    print("EXPERIMENTOS SEA - RESULTADOS")
    print("=" * 60)
    promedio = sum(f["consumo_sea"] for f in filas) / len(filas)
    for f in filas:
        print(f"{f['escenario']}: {f['algoritmo']} | "
              f"Consumo SEA={f['consumo_sea']} | Ahorro={f['ahorro_porcentaje']}%")
    print("-" * 60)
    print(f"Consumo promedio SEA: {promedio:.3f}")
    print(f"Ahorro energetico promedio: {(1.0 - promedio) * 100:.1f}%")
    print(f"\nCSV generado en: {salida}")


if __name__ == "__main__":
    main()
