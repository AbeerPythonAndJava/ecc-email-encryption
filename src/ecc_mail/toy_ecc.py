"""Educational, faithful re-implementation of the ORIGINAL Java algorithm.

⚠️  NOT SECURE — FOR TEACHING ONLY. The curve has only a few hundred points,
so the private key can be brute-forced instantly. Use :mod:`ecc_mail.crypto`
for real messages.

What the Java code (multi.java) did, and how it maps here:

=====================================  =====================================
Java                                   Python
=====================================  =====================================
a=7, b=9, n=491, G=(120,23)            ``ORIGINAL_CURVE``
``genral()`` point doubling loop       :meth:`Curve.double`
``add131()`` p != q addition            :meth:`Curve.add`
brute-force ``while(true)`` inverse     ``pow(x, -1, p)``  (O(log p))
"doubling 5 times" / "3 times"          :meth:`Curve.multiply` (double-and-add)
``empeding()`` x = index*10 + j         :func:`encode_char` (Koblitz)
Encryption: (kG, Pm + k·Q)              :func:`encrypt`
Decryption: Pm = C2 - d·C1              :func:`decrypt`
13 temporary .txt files                 plain return values (no disk I/O)
=====================================  =====================================

Bugs fixed compared with the Java version:
    * ``k`` was the constant 3 for every character → now random per character.
    * index*10+j exceeded p=491 for 'x','y','z' → K and alphabet are validated.
    * The emailed "cipher text" kept only one x-coordinate, so the recipient
      could not decrypt it; here the full ciphertext (C1, C2) is kept.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from typing import Optional

# ``None`` represents the point at infinity (the group identity element O).
Point = Optional[tuple[int, int]]

DEFAULT_ALPHABET = " " + string.ascii_letters + ".,!?"


@dataclass(frozen=True)
class Curve:
    """Short Weierstrass curve  y² = x³ + a·x + b  (mod p)."""

    p: int
    a: int
    b: int
    g: tuple[int, int]

    def __post_init__(self) -> None:
        if (4 * self.a**3 + 27 * self.b**2) % self.p == 0:
            raise ValueError("Singular curve: 4a³ + 27b² ≡ 0 (mod p).")
        if not self.is_on_curve(self.g):
            raise ValueError(f"Base point {self.g} is not on the curve.")

    # ---------- basic checks ----------
    def rhs(self, x: int) -> int:
        """Right-hand side x³ + a·x + b (mod p)."""
        return (x * x * x + self.a * x + self.b) % self.p

    def is_on_curve(self, pt: Point) -> bool:
        if pt is None:
            return True
        x, y = pt
        return (y * y - self.rhs(x)) % self.p == 0

    def negate(self, pt: Point) -> Point:
        if pt is None:
            return None
        x, y = pt
        return (x, (-y) % self.p)

    # ---------- group law ----------
    def add(self, p1: Point, p2: Point) -> Point:
        """P + Q using the chord (P≠Q) or tangent (P=Q) rule."""
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # P + (-P) = O
        if p1 == p2:
            # λ = (3x² + a) / 2y      — the "lamdah" loop in genral()
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)
        else:
            # λ = (y2 - y1) / (x2 - x1) — the loop in add131()
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p)
        lam %= self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def double(self, pt: Point) -> Point:
        return self.add(pt, pt)

    def multiply(self, k: int, pt: Point) -> Point:
        """Scalar multiplication k·P with the double-and-add algorithm."""
        if k < 0:
            return self.multiply(-k, self.negate(pt))
        result: Point = None
        addend = pt
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            k >>= 1
        return result

    def sqrt(self, v: int) -> Optional[int]:
        """Modular square root (requires p ≡ 3 mod 4). None if no root."""
        if self.p % 4 != 3:
            raise NotImplementedError("sqrt implemented only for p ≡ 3 (mod 4)")
        v %= self.p
        root = pow(v, (self.p + 1) // 4, self.p)
        return root if (root * root) % self.p == v else None


ORIGINAL_CURVE = Curve(p=491, a=7, b=9, g=(120, 23))


# ---------- Koblitz encoding (Java: empeding) ----------
def encode_char(
    ch: str, curve: Curve = ORIGINAL_CURVE, alphabet: str = DEFAULT_ALPHABET, k: int = 8
) -> tuple[int, int]:
    """Map a character to a curve point: try x = index·k + j, j = 1..k."""
    if len(alphabet) * k >= curve.p:
        raise ValueError("alphabet × k must be smaller than p")
    try:
        index = alphabet.index(ch)
    except ValueError:
        raise ValueError(f"Character {ch!r} is not in the alphabet") from None
    for j in range(1, k + 1):
        x = index * k + j
        y = curve.sqrt(curve.rhs(x))
        if y is not None:
            return (x, y)
    raise ValueError(f"No curve point found for {ch!r}; increase k")


def decode_point(
    pt: tuple[int, int], alphabet: str = DEFAULT_ALPHABET, k: int = 8
) -> str:
    """Inverse of :func:`encode_char`: index = (x - 1) // k."""
    return alphabet[(pt[0] - 1) // k]


# ---------- EC-ElGamal ----------
def generate_keypair(curve: Curve = ORIGINAL_CURVE) -> tuple[int, Point]:
    """Private scalar d and public point Q = d·G."""
    d = secrets.randbelow(curve.p - 2) + 2
    return d, curve.multiply(d, curve.g)


def encrypt(
    text: str, public: Point, curve: Curve = ORIGINAL_CURVE
) -> list[tuple[Point, Point]]:
    """Encrypt each character as (C1, C2) = (k·G, Pm + k·Q) with random k."""
    out = []
    for ch in text:
        pm = encode_char(ch, curve)
        k = secrets.randbelow(curve.p - 2) + 2
        c1 = curve.multiply(k, curve.g)
        c2 = curve.add(pm, curve.multiply(k, public))
        out.append((c1, c2))
    return out


def decrypt(
    cipher: list[tuple[Point, Point]], private: int, curve: Curve = ORIGINAL_CURVE
) -> str:
    """Recover Pm = C2 − d·C1 for each pair, then decode."""
    chars = []
    for c1, c2 in cipher:
        pm = curve.add(c2, curve.negate(curve.multiply(private, c1)))
        if pm is None:
            raise ValueError("Decryption produced the point at infinity")
        chars.append(decode_point(pm))
    return "".join(chars)


if __name__ == "__main__":  # quick classroom demo: python -m ecc_mail.toy_ecc
    d, q = generate_keypair()
    msg = "Hello ECC!"
    ct = encrypt(msg, q)
    print(f"private d = {d}, public Q = {q}")
    print("cipher    =", ct[:3], "...")
    print("decrypted =", decrypt(ct, d))
