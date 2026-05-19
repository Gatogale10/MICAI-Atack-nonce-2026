In this repository we update all the code about the capture,detection,attack.

# ECDSA Nonce Attack & AI-Based Detection — MICAI 2026

> **Breaking and Defending ECDSA in Real TLS Traffic: A Lattice Attack and AI-Based Detection Framework**
> Jorge Gael Lopez-Figueras, Eliseo Sarmiento — MICAI 2026, Chihuahua

---

## ¿Qué hace este proyecto?

Este repositorio demuestra dos cosas:

1. **ATAQUE**: Recuperar la clave privada de un servidor TLS real explotando
   una falla en la generación del nonce ECDSA (bits más significativos sesgados).
   Técnica: Hidden Number Problem + reducción de retículos (LLL/BKZ + Babai).

2. **DEFENSA**: Entrenar un clasificador (Random Forest) que detecta si un servidor
   TLS tiene nonces débiles en menos de un segundo, usando solo rasgos estadísticos
   de las firmas observadas.

---

## Estructura del proyecto

```
ecdsa-nonce-attack-micai2026/
├── server/              # Configuración del servidor TLS vulnerable
│   ├── openssl_patch/   # Parche para inducir sesgo en el nonce
│   ├── nginx_config/    # Config nginx (opcional)
│   └── setup_server.sh  # Script de instalación completo
├── capture/             # Captura y extracción de firmas TLS
│   ├── capture.sh       # Captura con tshark
│   └── parser_pcap.py   # Extrae (r, s, h) del .pcap
├── attack/              # Módulo de ataque reticular
│   ├── babai.py         # Algoritmo de Babai (Nearest Plane CVP)
│   ├── hnp_lattice.py   # Construcción del retículo HNP
│   └── lattice_attack.py# Orquestador del ataque completo
├── detector/            # Módulo de detección por IA
│   ├── features.py      # Extracción de rasgos estadísticos
│   ├── train.py         # Entrenamiento del clasificador
│   └── predict.py       # Inferencia sobre nuevas firmas
├── eval/                # Evaluación empírica sistemática
│   ├── run_experiments.py  # Genera mapa de calor (t, b)
│   └── plot_results.py     # Figuras para el paper
├── data/                # Datasets (.json con firmas capturadas)
├── paper/               # Artículo LaTeX
└── requirements.txt
```

---

## Quickstart

### 1. Instalar dependencias

```bash
pip install -r requirements.txt
sudo apt install -y tshark build-essential git perl
```

### 2. Configurar el servidor vulnerable

```bash
# En el servidor (Ubuntu 22.04)
bash server/setup_server.sh --bits 8   # induce 8 MSB = 0 en el nonce
```

### 3. Capturar firmas TLS

```bash
# Terminal 1: capturar tráfico
bash capture/capture.sh --interface lo --port 4433 --output data/sigs_b8.pcap

# Terminal 2: generar conexiones
for i in $(seq 1 200); do
    curl -sk --tlsv1.2 --tls-max 1.2 https://127.0.0.1:4433/ > /dev/null
done
```

### 4. Extraer firmas del pcap

```bash
python3 capture/parser_pcap.py \
    --pcap data/sigs_b8.pcap \
    --log  server/openssl_patch/sig_log.json \
    --out  data/signatures_b8.json
```

### 5. Ejecutar el ataque

```bash
python3 attack/lattice_attack.py \
    --sigs data/signatures_b8.json \
    --bits 8 \
    --nsigs 40 \
    --bkz  20 \
    --key  server/server_key.pem
```

### 6. Entrenar y usar el detector IA

```bash
# Generar dataset y entrenar
python3 detector/train.py --samples 600 --window 30

# Detectar si un conjunto de firmas proviene de un servidor vulnerable
python3 detector/predict.py --sigs data/signatures_b8.json
```

### 7. Evaluación sistemática (genera figuras del paper)

```bash
python3 eval/run_experiments.py --sigs data/signatures_b8.json
python3 eval/plot_results.py
```

---

## Parámetros importantes

| Parámetro | Descripción | Valor recomendado |
|-----------|-------------|-------------------|
| `b` | Bits filtrados (MSB del nonce = 0) | 8–16 para ataques viables |
| `t` | Número de firmas usadas | 30–50 con b=8 |
| `beta` | Blocksize de BKZ | 20–30 |
| `window` | Firmas que usa el detector IA | 20–30 |

---

## CITA

```bibtex
@inproceedings{lopez2026ecdsa,
  title     = {Breaking and Defending ECDSA in Real TLS Traffic: 
               A Lattice Attack and AI-Based Detection Framework},
  author    = {Lopez-Figueras,Leonardo Rivera Zacarias and  Sarmiento, Eliseo},
  booktitle = {Mexican International Conference on Artificial Intelligence (MICAI)},
  year      = {2026},
  publisher = {Springer LNAI}
}
```

---

## ⚠️ Aviso legal
Este código es exclusivamente para investigación académica en un entorno
controlado (servidor propio).