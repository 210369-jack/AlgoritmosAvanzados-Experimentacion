# Arquitectura SEA: Criptografía Adaptativa para Smart Cities

Optimización de Seguridad Post-Cuántica e Integración de Criptografía
Híbrida para Smart Cities.

**Asignatura:** Algoritmos Avanzados
**Docente:** Huillca Huallparimachi, Raúl
**Universidad Nacional San Antonio Abad del Cusco**

## Integrantes

- Titto Huaman, Jack Eliezer
- Melo Cajahuillca, Mario Gabriel
- Alvarez Catunta, Angel Ismael
- Sota Escalante, Baruc

## Descripción

SEA (Selective Energy-Aware Cryptography Architecture) es un modelo de
selección dinámica de algoritmos criptográficos según el contexto
energético, la sensibilidad de los datos y el tipo de dispositivo. La
arquitectura integra criptografía híbrida combinando algoritmos
asimétricos (ECC, Kyber) y simétricos (AES, ASCON, ChaCha20), priorizando
los de menor consumo para operaciones continuas y Kyber para resistencia
post-cuántica.

Resultados: ahorro energético promedio del 57.5%, hasta 85% en batería
crítica, y extensión de la vida útil de los sensores en un factor de 2.5x.

## Estructura

- `src/algoritmos/`: implementación individual de cada algoritmo
  (ASCON-128, AES-256-GCM, ECC, Kyber-512, ChaCha20-Poly1305).
- `src/sea/`: motor CryptoEngine con el selector adaptativo.
- `experimentos/`: scripts de ejecución de los experimentos.
- `datos/`: resultados experimentales en formato CSV.
- `docs/`: informe del proyecto.

## Instalación
