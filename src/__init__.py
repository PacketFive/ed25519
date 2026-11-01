# SPDX-License-Identifier: GPL-2.0
"""Ed25519 signatures of RFC 8032 in Python, with no compiled code.

A SigningKey is made from a 32-byte seed and signs messages; a
VerifyingKey is made from a 32-byte public key and checks 64-byte
signatures. Keys and signatures are the raw byte strings of RFC 8032
section 5.1, so they interoperate with any other implementation.
"""

from .keys import BadSignatureError, SigningKey, VerifyingKey

__version__ = "1.0.0"

__all__ = ["BadSignatureError", "SigningKey", "VerifyingKey", "__version__"]
