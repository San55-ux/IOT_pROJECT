"""
Schnorr Identification & Zero-Knowledge Proof Cryptographic Engine
Implements secp256k1 Elliptic Curve group operations and Schnorr Identification Protocol.
Pure-Python implementation with zero external C-dependencies for full portability and auditability.
"""

import os
import hashlib
import secrets
from typing import Tuple, Optional

# ==============================================================================
# secp256k1 Curve Parameters
# y^2 = x^3 + 7 (mod p)
# ==============================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
POINT_INFINITY = (None, None)

Point = Tuple[Optional[int], Optional[int]]


def inverse_mod(k: int, m: int = ORDER) -> int:
    """Computes the modular multiplicative inverse: k^(-1) mod m."""
    if k == 0:
        raise ZeroDivisionError("Cannot invert zero modulo m")
    if k < 0:
        return m - inverse_mod(-k, m)
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = m, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_s % m


def is_on_curve(point: Point) -> bool:
    """Verifies that a given point lies on the secp256k1 curve."""
    if point == POINT_INFINITY:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_neg(point: Point) -> Point:
    """Returns -P on the elliptic curve."""
    if point == POINT_INFINITY:
        return POINT_INFINITY
    x, y = point
    return (x, (-y) % P)


def point_add(p1: Point, p2: Point) -> Point:
    """Adds two points on the secp256k1 curve."""
    if p1 == POINT_INFINITY:
        return p2
    if p2 == POINT_INFINITY:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return POINT_INFINITY

    if x1 == x2:
        # Point doubling
        lam = ((3 * x1 * x1 + A) * pow(2 * y1, P - 2, P)) % P
    else:
        # Point addition
        lam = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k: int, point: Point = G) -> Point:
    """Multiplies a point by an integer scalar using double-and-add."""
    if point == POINT_INFINITY or k % ORDER == 0:
        return POINT_INFINITY

    k = k % ORDER
    result = POINT_INFINITY
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def encode_point(point: Point, compressed: bool = True) -> str:
    """Serializes an elliptic curve point to hex format."""
    if point == POINT_INFINITY:
        return "00"
    x, y = point
    x_bytes = x.to_bytes(32, byteorder="big")
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return (prefix + x_bytes).hex()
    else:
        y_bytes = y.to_bytes(32, byteorder="big")
        return (b"\x04" + x_bytes + y_bytes).hex()


def decode_point(hex_str: str) -> Point:
    """Deserializes an elliptic curve point from hex format."""
    data = bytes.fromhex(hex_str)
    if len(data) == 1 and data[0] == 0:
        return POINT_INFINITY

    if len(data) == 33:
        prefix = data[0]
        if prefix not in (2, 3):
            raise ValueError(f"Invalid compressed point prefix: {prefix}")
        x = int.from_bytes(data[1:], byteorder="big")
        y_sq = (pow(x, 3, P) + B) % P
        # Modular square root for P = 3 (mod 4)
        y = pow(y_sq, (P + 1) // 4, P)
        if (y % 2 == 0 and prefix == 3) or (y % 2 == 1 and prefix == 2):
            y = P - y
        point = (x, y)
        if not is_on_curve(point):
            raise ValueError("Point decoded from compressed hex does not lie on curve")
        return point

    elif len(data) == 65:
        if data[0] != 4:
            raise ValueError(f"Invalid uncompressed point prefix: {data[0]}")
        x = int.from_bytes(data[1:33], byteorder="big")
        y = int.from_bytes(data[33:], byteorder="big")
        point = (x, y)
        if not is_on_curve(point):
            raise ValueError("Point decoded from uncompressed hex does not lie on curve")
        return point
    else:
        raise ValueError(f"Unexpected public key length: {len(data)} bytes")


# ==============================================================================
# Schnorr Identification Protocol Core Logic
# ==============================================================================

class SchnorrProtocol:
    """
    Implements 3-pass Interactive Schnorr Identification:
      1. Prover: generates ephemeral nonce k, commitment R = k * G
      2. Verifier: generates fresh challenge c in [1, q-1]
      3. Prover: computes response s = (k + c * x) mod q
      4. Verifier: verifies that s * G == R + c * Y
    """

    @staticmethod
    def derive_public_key(private_secret: int) -> Point:
        """Derives public key Y = x * G from private secret x."""
        if not (1 <= private_secret < ORDER):
            raise ValueError("Private secret outside valid scalar field [1, q-1]")
        return scalar_mult(private_secret, G)

    @staticmethod
    def generate_commitment() -> Tuple[int, Point]:
        """
        Prover step:
        Generates ephemeral secret nonce k and commitment point R = k * G.
        """
        k = secrets.randbelow(ORDER - 1) + 1
        R = scalar_mult(k, G)
        return k, R

    @staticmethod
    def generate_challenge() -> int:
        """
        Gateway/Verifier step:
        Generates fresh cryptographically secure challenge c in [1, q-1].
        """
        return secrets.randbelow(ORDER - 1) + 1

    @staticmethod
    def compute_response(k: int, c: int, x: int) -> int:
        """
        Prover step:
        Computes response s = (k + c * x) mod q.
        """
        return (k + c * x) % ORDER

    @staticmethod
    def verify_proof(public_key: Point, commitment: Point, challenge: int, response: int) -> bool:
        """
        Gateway/Verifier step:
        Verifies whether s * G == R + c * Y.
        Ensures response s and challenge c are valid scalars.
        """
        if not (1 <= response < ORDER):
            return False
        if not (1 <= challenge < ORDER):
            return False
        if commitment == POINT_INFINITY or not is_on_curve(commitment):
            return False
        if public_key == POINT_INFINITY or not is_on_curve(public_key):
            return False

        # Left-hand side: s * G
        lhs = scalar_mult(response, G)

        # Right-hand side: R + c * Y
        cY = scalar_mult(challenge, public_key)
        rhs = point_add(commitment, cY)

        return lhs == rhs

    @staticmethod
    def compute_fiat_shamir_challenge(device_id: str, public_key: Point, commitment: Point, nonce: str) -> int:
        """
        Non-interactive mode (Fiat-Shamir heuristic):
        c = H(device_id || Y || R || nonce) mod q
        Used for evaluation and comparison against interactive mode.
        """
        h = hashlib.sha256()
        h.update(device_id.encode("utf-8"))
        h.update(encode_point(public_key).encode("utf-8"))
        h.update(encode_point(commitment).encode("utf-8"))
        h.update(nonce.encode("utf-8"))
        digest = h.digest()
        c = int.from_bytes(digest, byteorder="big") % ORDER
        return c if c != 0 else 1
