"""
babai.py
========
Implementación del algoritmo de Babai Nearest Plane para el Closest Vector
Problem (CVP), usando aritmética de punto flotante de alta precisión con mpmath.

Referencia:
    Babai, L. (1986). On Lovász' lattice reduction and the nearest lattice point problem.
    Combinatorica, 6(1), 1–13.

Uso:
    from babai import babai_nearest_plane
    v, coeffs = babai_nearest_plane(B_reduced, target)
"""

from __future__ import annotations

import sys
from typing import Optional

# ── Intentar importar mpmath para alta precisión ────────────────────────────
try:
    import mpmath
    _HAS_MPMATH = True
except ImportError:
    _HAS_MPMATH = False

# ── Intentar importar fpylll para la reducción BKZ ──────────────────────────
try:
    from fpylll import IntegerMatrix, LLL, BKZ, GSO, MatGSO
    _HAS_FPYLLL = True
except ImportError:
    _HAS_FPYLLL = False


# ════════════════════════════════════════════════════════════════════════════
# Gram-Schmidt con mpmath (alta precisión, 512 bits)
# ════════════════════════════════════════════════════════════════════════════

def _gram_schmidt_mpmath(B_int: list[list[int]],
                         prec: int = 512) -> tuple:
    """
    Ortogonalización de Gram-Schmidt con mpmath (alta precisión).

    Parámetros:
        B_int : lista de listas de enteros (filas = vectores base)
        prec  : precisión en bits (default 512)

    Retorna:
        (B_star, mu) donde B_star son los vectores ortogonalizados y
        mu son los coeficientes de Gram-Schmidt.
    """
    if not _HAS_MPMATH:
        raise ImportError("mpmath no está instalado. pip install mpmath")

    mpmath.mp.prec = prec

    n = len(B_int)
    m = len(B_int[0])

    # Convertir a matriz mpmath
    B = [[mpmath.mpf(x) for x in row] for row in B_int]

    B_star = [[mpmath.mpf(0)] * m for _ in range(n)]
    mu = [[mpmath.mpf(0)] * n for _ in range(n)]

    for i in range(n):
        B_star[i] = B[i][:]  # copia
        for j in range(i):
            # mu[i][j] = <B[i], B_star[j]> / <B_star[j], B_star[j]>
            num = sum(B[i][k] * B_star[j][k] for k in range(m))
            den = sum(B_star[j][k] ** 2 for k in range(m))
            if den == 0:
                mu[i][j] = mpmath.mpf(0)
            else:
                mu[i][j] = num / den
            for k in range(m):
                B_star[i][k] -= mu[i][j] * B_star[j][k]

    return B_star, mu


# ════════════════════════════════════════════════════════════════════════════
# Babai Nearest Plane (método principal)
# ════════════════════════════════════════════════════════════════════════════

def babai_nearest_plane(B_int: list[list[int]],
                        target_int: list[int],
                        prec: int = 512) -> tuple[list[int], list[int]]:
    """
    Algoritmo de Babai Nearest Plane (CVP).

    Dada una base reducida B (filas = vectores base) y un vector objetivo t,
    retorna el vector del retículo más cercano a t.

    Parámetros:
        B_int      : lista de n listas de m enteros (base reducida, fila mayor = primero)
        target_int : lista de m enteros (vector objetivo)
        prec       : precisión en bits para mpmath

    Retorna:
        (v, coeffs) donde:
          v      = vector del retículo más cercano (lista de ints)
          coeffs = coeficientes enteros tal que v = sum(c_i * B[i])
    """
    if not _HAS_MPMATH:
        raise ImportError("mpmath no está instalado. pip install mpmath")

    mpmath.mp.prec = prec

    n = len(B_int)
    m = len(B_int[0])

    # Gram-Schmidt
    B_star, _ = _gram_schmidt_mpmath(B_int, prec)

    # Convertir B a mpmath para los cálculos
    B_mp = [[mpmath.mpf(x) for x in row] for row in B_int]
    t    = [mpmath.mpf(x) for x in target_int]

    # Babai rounding: procesar desde el vector más largo al más corto
    w = t[:]
    coeffs = [0] * n

    for i in range(n - 1, -1, -1):
        # Proyección de w sobre B_star[i]
        b_star_i = B_star[i]

        # c_i = <w, b_star_i> / <b_star_i, b_star_i>
        num = sum(w[k] * b_star_i[k] for k in range(m))
        den = sum(b_star_i[k] ** 2 for k in range(m))

        if den == 0:
            c_i = mpmath.mpf(0)
        else:
            c_i = num / den

        # Redondear al entero más cercano
        ci_int = int(mpmath.nint(c_i))
        coeffs[i] = ci_int

        # Actualizar w: w <- w - ci * B[i]
        for k in range(m):
            w[k] -= ci_int * B_mp[i][k]

    # Reconstruir el vector del retículo: v = sum(c_i * B[i])
    v = [0] * m
    for i in range(n):
        for k in range(m):
            v[k] += coeffs[i] * B_int[i][k]

    return v, coeffs


# ════════════════════════════════════════════════════════════════════════════
# Versión con fpylll (alternativa, usa GSO interno de fpylll)
# ════════════════════════════════════════════════════════════════════════════

def babai_fpylll(M_reduced: "IntegerMatrix",
                 target: list[int]) -> list[int]:
    """
    Babai usando fpylll's GSO interno. Más rápido pero menos preciso para
    enteros muy grandes.

    Parámetros:
        M_reduced : IntegerMatrix de fpylll ya reducida (LLL/BKZ)
        target    : vector objetivo como lista de enteros

    Retorna:
        v : vector del retículo más cercano (lista de enteros)
    """
    if not _HAS_FPYLLL:
        raise ImportError("fpylll no está instalado. pip install fpylll")

    n = M_reduced.nrows
    m = M_reduced.ncols

    # Extraer la base como lista de listas
    B = [[M_reduced[i, j] for j in range(m)] for i in range(n)]

    # Usar nuestra implementación mpmath
    v, _ = babai_nearest_plane(B, target, prec=768)
    return v


# ════════════════════════════════════════════════════════════════════════════
# Utilidades
# ════════════════════════════════════════════════════════════════════════════

def lattice_vector_norm_sq(v: list[int]) -> int:
    """Norma al cuadrado de un vector de enteros."""
    return sum(x * x for x in v)


def print_basis_norms(B: list[list[int]], label: str = "Base") -> None:
    """Imprime las normas de los vectores de la base (útil para debugging)."""
    print(f"  {label} (primeros 5 vectores):")
    for i, row in enumerate(B[:5]):
        norm_sq = lattice_vector_norm_sq(row)
        bits = norm_sq.bit_length() // 2
        print(f"    v[{i}]: ||v||² ≈ 2^{bits}")


# ════════════════════════════════════════════════════════════════════════════
# Test rápido
# ════════════════════════════════════════════════════════════════════════════

def _test_babai():
    """Test básico del algoritmo en dimensión pequeña."""
    import random
    random.seed(42)
    n = 5
    # Base aleatoria de enteros pequeños
    B = [[random.randint(-10, 10) for _ in range(n)] for _ in range(n)]
    # Asegurar que es base válida (det != 0) sumando la identidad
    for i in range(n):
        B[i][i] += 100

    # Vector objetivo: un punto del retículo + ruido pequeño
    coeffs_true = [random.randint(0, 3) for _ in range(n)]
    v_true = [sum(coeffs_true[i] * B[i][j] for i in range(n)) for j in range(n)]
    noise = [random.randint(-2, 2) for _ in range(n)]
    target = [v_true[j] + noise[j] for j in range(n)]

    v_found, c_found = babai_nearest_plane(B, target)
    dist = sum((v_found[j] - v_true[j]) ** 2 for j in range(n)) ** 0.5

    print(f"  [TEST] Babai: distancia al vector real = {dist:.4f}")
    assert dist < 5.0, f"Test fallido: distancia {dist} demasiado grande"
    print("  [TEST] OK")


if __name__ == "__main__":
    print("Ejecutando test de Babai...")
    _test_babai()