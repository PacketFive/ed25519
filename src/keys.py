# SPDX-License-Identifier: GPL-2.0
"""Ed25519 keys, signing and verification (RFC 8032 section 5.1)."""

from __future__ import annotations

import hashlib
import os

from . import curve


class BadSignatureError(Exception):
    """A signature does not verify for the message and key it was checked against."""


def _hash_scalar(*parts: bytes) -> int:
    digest = hashlib.sha512()
    for part in parts:
        digest.update(part)
    return int.from_bytes(digest.digest(), "little") % curve.L


def _bytes(value: object, length: int, what: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{what} must be bytes, not {type(value).__name__}")
    data = bytes(value)
    if len(data) != length:
        raise ValueError(f"{what} must be {length} bytes, not {len(data)}")
    return data


class VerifyingKey:
    """An Ed25519 public key, which checks signatures."""

    __slots__ = ("_encoded", "_point")

    def __init__(self, public: bytes) -> None:
        """Hold the 32-byte public key ``public``.

        Raises TypeError if it is not bytes and ValueError if it has
        another length or does not encode a point of the curve.
        """
        encoded = _bytes(public, 32, "an Ed25519 public key")
        point = curve.decode(encoded)
        if point is None:
            raise ValueError("an Ed25519 public key must encode a point of the curve")
        self._encoded = encoded
        self._point = point

    @property
    def encoded(self) -> bytes:
        """The 32 bytes of the key."""
        return self._encoded

    def verify(self, signature: bytes, message: bytes) -> None:
        """Check ``signature`` over ``message``. Raises BadSignatureError if it fails.

        The check is that of RFC 8032 section 5.1.7 without the cofactor:
        S must be less than L and the encoding of [S]B - [k]A must equal
        R byte for byte, as in OpenSSL and libsodium, so a signature this
        method accepts is accepted there too.
        """
        if not isinstance(signature, (bytes, bytearray, memoryview)) or len(signature) != 64:
            raise BadSignatureError("an Ed25519 signature is 64 bytes")
        signature = bytes(signature)
        r_bytes, s = signature[:32], int.from_bytes(signature[32:], "little")
        if s >= curve.L:
            raise BadSignatureError("the signature's S is not less than the group order")
        k = _hash_scalar(r_bytes, self._encoded, bytes(message))
        check = curve.add(curve.multiply_base(s), curve.negate(curve.multiply(k, self._point)))
        if curve.encode(check) != r_bytes:
            raise BadSignatureError("the signature does not match the message and key")

    def __eq__(self, other: object) -> bool:
        """Return whether ``other`` is a VerifyingKey with the same bytes."""
        return isinstance(other, VerifyingKey) and other._encoded == self._encoded

    def __hash__(self) -> int:
        """Hash the key's bytes."""
        return hash(self._encoded)

    def __repr__(self) -> str:
        """Show the key in hex."""
        return f"VerifyingKey({self._encoded.hex()!r})"


class SigningKey:
    """An Ed25519 secret key, made from a 32-byte seed, which signs messages."""

    __slots__ = ("_prefix", "_scalar", "_seed", "_verifying_key")

    def __init__(self, seed: bytes) -> None:
        """Hold the key of the 32-byte ``seed``.

        Raises TypeError if it is not bytes and ValueError if it has
        another length.
        """
        self._seed = _bytes(seed, 32, "an Ed25519 seed")
        digest = hashlib.sha512(self._seed).digest()
        scalar = int.from_bytes(digest[:32], "little")
        scalar &= (1 << 254) - 8
        scalar |= 1 << 254
        self._scalar = scalar
        self._prefix = digest[32:]
        self._verifying_key = VerifyingKey(curve.encode(curve.multiply_base(scalar)))

    @classmethod
    def generate(cls) -> SigningKey:
        """Return a new key from 32 bytes of ``os.urandom``."""
        return cls(os.urandom(32))

    @property
    def seed(self) -> bytes:
        """The 32-byte seed, which is the secret key's stored form."""
        return self._seed

    @property
    def verifying_key(self) -> VerifyingKey:
        """The public key that checks this key's signatures."""
        return self._verifying_key

    def sign(self, message: bytes) -> bytes:
        """Return the 64-byte signature of ``message`` (RFC 8032 section 5.1.6)."""
        message = bytes(message)
        public = self._verifying_key.encoded
        r = _hash_scalar(self._prefix, message)
        r_bytes = curve.encode(curve.multiply_base(r))
        k = _hash_scalar(r_bytes, public, message)
        s = (r + k * self._scalar) % curve.L
        return r_bytes + s.to_bytes(32, "little")

    def __repr__(self) -> str:
        """Show the public key only."""
        return f"SigningKey(<secret>, public={self._verifying_key.encoded.hex()!r})"
