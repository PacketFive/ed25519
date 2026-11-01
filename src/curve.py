# SPDX-License-Identifier: GPL-2.0
"""The group of the twisted Edwards curve edwards25519 (RFC 8032 section 5.1).

Points are kept in extended homogeneous coordinates (X, Y, Z, T) with
x = X/Z, y = Y/Z and x*y = T/Z, so addition needs no inversion. Every
operation runs in time that depends on its inputs: Python integers give
no constant-time arithmetic.
"""

from __future__ import annotations

P = 2**255 - 19
"""The prime of the field."""

L = 2**252 + 27742317777372353535851937790883648493
"""The order of the base point."""

D = -121665 * pow(121666, -1, P) % P
"""The curve constant d of -x^2 + y^2 = 1 + d*x^2*y^2."""

_SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]

IDENTITY: Point = (0, 1, 1, 0)

_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
BASE: Point = (_BX, _BY, 1, _BX * _BY % P)
"""The base point B, whose y coordinate is 4/5."""


def add(p: Point, q: Point) -> Point:
    """Return p + q, with the formulas of RFC 8032 section 5.1.4."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    e = 2 * z1 * z2 % P
    f, g, h, k = b - a, e - c, e + c, b + a
    return (f * g % P, h * k % P, g * h % P, f * k % P)


def double(p: Point) -> Point:
    """Return 2p, with the doubling formulas of RFC 8032 section 5.1.4."""
    x1, y1, z1, _ = p
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    h = a + b
    e = h - (x1 + y1) * (x1 + y1)
    g = a - b
    f = c + g
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def negate(p: Point) -> Point:
    """Return -p."""
    x, y, z, t = p
    return (-x % P, y, z, -t % P)


def multiply(scalar: int, p: Point) -> Point:
    """Return scalar * p, for a scalar of zero or more."""
    result = IDENTITY
    for bit in bin(scalar)[2:]:
        result = double(result)
        if bit == "1":
            result = add(result, p)
    return result


_BASE_TABLE: list[Point] = []
_point = BASE
for _ in range(256):
    _BASE_TABLE.append(_point)
    _point = double(_point)


def multiply_base(scalar: int) -> Point:
    """Return scalar * B through a table of B * 2^i, for 0 <= scalar < 2^256."""
    result = IDENTITY
    i = 0
    while scalar:
        if scalar & 1:
            result = add(result, _BASE_TABLE[i])
        scalar >>= 1
        i += 1
    return result


def encode(p: Point) -> bytes:
    """Return the 32-byte encoding of p (RFC 8032 section 5.1.2)."""
    x, y, z, _ = p
    inverse = pow(z, P - 2, P)
    x, y = x * inverse % P, y * inverse % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def decode(data: bytes) -> Point | None:
    """Return the point of a 32-byte encoding, or None if it encodes none.

    Encodings with y of P or more, and those with x = 0 and the sign bit
    set, are refused as RFC 8032 section 5.1.3 asks.
    """
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    check = v * x * x % P
    if check == (-u) % P:
        x = x * _SQRT_M1 % P
    elif check != u:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)
