#!/usr/bin/env python3
"""
parser_pcap.py
==============
Extrae tuplas (r, s, h) de firmas ECDSA a partir de:
  1. El log JSON generado por el servidor OpenSSL parchado (método principal).
  2. Un archivo .pcap capturado con tshark (método alternativo via tshark).

Salida: data/signatures_b{N}.json con la lista de firmas lista para el ataque.

Uso:
    # Método 1 (recomendado, usa el log del servidor):
    python3 capture/parser_pcap.py \
        --log  server/openssl_patch/sig_log.json \
        --out  data/signatures_b8.json

    # Método 2 (del .pcap, requiere tshark instalado):
    python3 capture/parser_pcap.py \
        --pcap data/capture.pcap \
        --out  data/signatures_b8.json

    # Ambos + verificar con la clave pública:
    python3 capture/parser_pcap.py \
        --log  server/openssl_patch/sig_log.json \
        --pcap data/capture.pcap \
        --cert server/server_cert.pem \
        --out  data/signatures_b8.json
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


# ── Parámetros de secp256r1 ──────────────────────────────────────────────────
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_BITS = 256


# ════════════════════════════════════════════════════════════════════════════
# Método 1: leer el log del servidor OpenSSL parchado
# ════════════════════════════════════════════════════════════════════════════

def parse_server_log(log_path: str) -> list[dict]:
    """
    Lee el archivo de log generado por el servidor OpenSSL parchado.
    Cada línea del log es un JSON con campos: r, s, h (hexadecimal).

    Retorna lista de dicts:
        [{"r": int, "s": int, "h": int}, ...]
    """
    sigs = []
    path = Path(log_path)
    if not path.exists():
        print(f"  [LOG] Archivo no encontrado: {log_path}")
        return []

    with open(path, "r") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line == "":
                continue
            try:
                obj = json.loads(line)
                r = int(obj["r"], 16)
                s = int(obj["s"], 16)
                h = int(obj["h"], 16)

                # Validación básica
                if not (1 <= r < P256_N and 1 <= s < P256_N):
                    print(f"  [LOG] Línea {lineno}: r o s fuera de rango, saltando.")
                    continue

                sigs.append({"r": r, "s": s, "h": h,
                              "r_hex": hex(r), "s_hex": hex(s), "h_hex": hex(h),
                              "source": "server_log"})
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"  [LOG] Línea {lineno}: error de parseo ({e}), saltando.")
                continue

    print(f"  [LOG] {len(sigs)} firmas leídas de {log_path}")
    return sigs


# ════════════════════════════════════════════════════════════════════════════
# Método 2: extraer del .pcap con tshark
# ════════════════════════════════════════════════════════════════════════════

def parse_ecdsa_der(der_bytes: bytes):
    """
    Parsea una firma ECDSA en formato DER y retorna (r, s) como enteros.
    Formato: 30 [len] 02 [len_r] [r] 02 [len_s] [s]
    """
    try:
        idx = 0
        # Header 0x30
        if der_bytes[idx] != 0x30:
            return None, None
        idx += 1

        # Longitud total (puede ser short o long form)
        if der_bytes[idx] & 0x80:
            n_len_bytes = der_bytes[idx] & 0x7F
            idx += 1 + n_len_bytes
        else:
            idx += 1

        # Primer entero: r
        if der_bytes[idx] != 0x02:
            return None, None
        idx += 1
        r_len = der_bytes[idx]
        idx += 1
        r_bytes = der_bytes[idx: idx + r_len]
        r = int.from_bytes(r_bytes, 'big')
        idx += r_len

        # Segundo entero: s
        if der_bytes[idx] != 0x02:
            return None, None
        idx += 1
        s_len = der_bytes[idx]
        idx += 1
        s_bytes = der_bytes[idx: idx + s_len]
        s = int.from_bytes(s_bytes, 'big')

        return r, s

    except (IndexError, ValueError):
        return None, None


def parse_pcap_tshark(pcap_path: str) -> list[dict]:
    """
    Usa tshark para extraer firmas ECDSA del mensaje ServerKeyExchange (TLS 1.2).

    IMPORTANTE: en TLS 1.2 el servidor firma:
        SHA256(ClientRandom || ServerRandom || ECParams || ECPoint)
    Este método extrae r, s del campo de firma.
    Para el hash h, intenta reconstruirlo desde los datos del handshake.

    Retorna lista de dicts: [{"r": int, "s": int, "h": int | None}, ...]
    """
    if not Path(pcap_path).exists():
        print(f"  [PCAP] Archivo no encontrado: {pcap_path}")
        return []

    # ── Extraer ClientRandom, ServerRandom, ServerKeyExchange signature ──
    print(f"  [PCAP] Procesando {pcap_path} con tshark...")

    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "ssl.handshake.type == 12",      # ServerKeyExchange
        "-T", "fields",
        "-e", "frame.number",
        "-e", "tls.handshake.sig",              # Firma DER (hex)
        "-e", "tls.handshake.sig_hash_alg",     # Hash algorithm
        "-e", "ip.src",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"  [PCAP] Error ejecutando tshark: {e}")
        print("         ¿Está tshark instalado? sudo apt install tshark")
        return []

    sigs = []
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split("\t")
        if len(parts) < 2 or not parts[1]:
            continue

        # Parsear la firma DER
        sig_hex = parts[1].replace(":", "").replace(" ", "")
        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            continue

        r, s = parse_ecdsa_der(sig_bytes)
        if r is None or not (1 <= r < P256_N and 1 <= s < P256_N):
            continue

        # El hash h no puede reconstruirse fácilmente del pcap sin las claves de sesión
        # Se marca como None; el ataque puede continuar si se tienen los h del log del servidor
        sigs.append({
            "r": r, "s": s, "h": None,
            "r_hex": hex(r), "s_hex": hex(s), "h_hex": None,
            "source": "pcap",
            "frame": parts[0]
        })

    print(f"  [PCAP] {len(sigs)} firmas extraídas del pcap.")
    if sigs and sigs[0]["h"] is None:
        print("  [PCAP] NOTA: hash h=None. Usar --log para obtener h del servidor.")

    return sigs


# ════════════════════════════════════════════════════════════════════════════
# Verificación de firmas
# ════════════════════════════════════════════════════════════════════════════

def verify_signatures(sigs: list[dict], cert_pem: str) -> tuple[list[dict], int]:
    """
    Verifica que las firmas son válidas con la clave pública del certificado.
    Retorna (sigs_válidas, n_inválidas).
    Requiere: pip install cryptography
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature
        )
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        print("  [VER] cryptography no instalada, saltando verificación.")
        return sigs, 0

    with open(cert_pem, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    pub_key = cert.public_key()

    valid, invalid = [], 0
    for sig in sigs:
        if sig["h"] is None:
            valid.append(sig)
            continue
        try:
            # Reconstruir la firma DER desde r, s
            der = encode_dss_signature(sig["r"], sig["s"])
            # El digest ya está hasheado (Prehashed)
            from cryptography.hazmat.primitives.asymmetric.utils import (
                decode_dss_signature
            )
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicKey
            )
            from cryptography.hazmat.primitives.hashes import SHA256
            # Verificar con el hash h directamente
            h_bytes = sig["h"].to_bytes(32, "big")
            from cryptography.hazmat.primitives.asymmetric.ec import (
                ECDSA
            )
            from cryptography.hazmat.primitives.asymmetric.utils import (
                encode_dss_signature
            )
            pub_key.verify(der, h_bytes,
                           ECDSA(hashes.Prehashed(hashes.SHA256())))
            valid.append(sig)
        except (InvalidSignature, Exception):
            invalid += 1

    return valid, invalid


# ════════════════════════════════════════════════════════════════════════════
# Análisis estadístico del sesgo
# ════════════════════════════════════════════════════════════════════════════

def analyze_bias(sigs: list[dict], b: int = 8) -> None:
    """
    Analiza si el sesgo de b bits es visible en las firmas capturadas.
    Si el ataque funciona, los b MSB de los nonces k deberían ser 0.
    Esto se refleja estadísticamente en la distribución de r.
    """
    if not sigs:
        return

    rs = [sig["r"] for sig in sigs]
    n = P256_N
    shift = P256_BITS - b

    # Contar cuántos r tienen los b MSB = 0
    # Nota: r = [k*G]_x mod n, el sesgo de k se refleja en r de forma indirecta
    msb_zero = sum(1 for r in rs if (r >> shift) == 0)

    import math
    entropy = 0.0
    freq = {}
    for r in rs:
        key = r >> (P256_BITS - 8)
        freq[key] = freq.get(key, 0) + 1
    for cnt in freq.values():
        p = cnt / len(rs)
        entropy -= p * math.log2(p)

    print(f"\n  === Análisis del sesgo ===")
    print(f"  Total firmas: {len(sigs)}")
    print(f"  {b} MSB de r = 0: {msb_zero}/{len(sigs)} "
          f"({100*msb_zero/len(sigs):.1f}%)")
    print(f"  Entropía de los 8 MSB de r: {entropy:.2f} / 8.00 bits")
    print(f"  (Entropía < 8 indica sesgo estadístico)")


# ════════════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Extrae firmas ECDSA de capturas TLS para el ataque reticular."
    )
    parser.add_argument("--log",  type=str, default=None,
                        help="Log JSON del servidor OpenSSL (recomendado)")
    parser.add_argument("--pcap", type=str, default=None,
                        help="Archivo .pcap capturado con tshark")
    parser.add_argument("--cert", type=str, default=None,
                        help="Certificado PEM del servidor (para verificación)")
    parser.add_argument("--out",  type=str, default="data/signatures.json",
                        help="Archivo JSON de salida")
    parser.add_argument("--bits", type=int, default=8,
                        help="Bits filtrados b (para análisis de sesgo)")
    parser.add_argument("--min",  type=int, default=20,
                        help="Mínimo de firmas requeridas")
    args = parser.parse_args()

    if args.log is None and args.pcap is None:
        print("ERROR: especifica --log y/o --pcap")
        sys.exit(1)

    all_sigs = []

    # ── Método 1: log del servidor ──
    if args.log:
        log_sigs = parse_server_log(args.log)
        all_sigs.extend(log_sigs)

    # ── Método 2: pcap ──
    if args.pcap:
        pcap_sigs = parse_pcap_tshark(args.pcap)

        # Si tenemos firmas del log, completar los h que faltan en el pcap
        if log_sigs := [s for s in all_sigs if s.get("source") == "server_log"]:
            log_by_r = {s["r"]: s for s in log_sigs}
            for sig in pcap_sigs:
                if sig["h"] is None and sig["r"] in log_by_r:
                    sig["h"] = log_by_r[sig["r"]]["h"]
                    sig["h_hex"] = hex(sig["h"])

        # Solo añadir las del pcap que no estén ya en all_sigs
        existing_r = {s["r"] for s in all_sigs}
        new_pcap = [s for s in pcap_sigs if s["r"] not in existing_r]
        all_sigs.extend(new_pcap)

    # ── Filtrar firmas sin h (no se pueden usar en el ataque) ──
    usable = [s for s in all_sigs if s.get("h") is not None]
    no_h   = len(all_sigs) - len(usable)

    if no_h > 0:
        print(f"  AVISO: {no_h} firmas sin hash h descartadas.")
        print(f"         Usa --log para obtener h directamente del servidor.")

    all_sigs = usable

    # ── Verificación opcional ──
    if args.cert and all_sigs:
        print(f"\n  Verificando firmas con certificado {args.cert}...")
        all_sigs, n_invalid = verify_signatures(all_sigs, args.cert)
        if n_invalid:
            print(f"  AVISO: {n_invalid} firmas inválidas descartadas.")

    # ── Estadísticas y análisis de sesgo ──
    analyze_bias(all_sigs, args.bits)

    if len(all_sigs) < args.min:
        print(f"\nAVISO: Solo {len(all_sigs)} firmas. "
              f"El ataque requiere al menos {args.min}.")
        print("  Solución: generar más conexiones al servidor.")

    # ── Serializar ──
    # Convertir enteros a strings para JSON (evitar overflow)
    output_sigs = []
    for sig in all_sigs:
        output_sigs.append({
            "r":     sig["r"],
            "s":     sig["s"],
            "h":     sig["h"],
            "r_hex": hex(sig["r"]),
            "s_hex": hex(sig["s"]),
            "h_hex": hex(sig["h"]),
        })

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(output_sigs, f, indent=2)

    print(f"\n  [{len(all_sigs)} firmas guardadas en {args.out}]")
    print(f"\nSiguiente paso:")
    print(f"  python3 attack/lattice_attack.py --sigs {args.out} "
          f"--bits {args.bits} --nsigs 40")


if __name__ == "__main__":
    main()