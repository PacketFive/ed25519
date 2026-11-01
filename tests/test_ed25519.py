# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path

import pytest

from pyrixos_ed25519 import BadSignatureError, SigningKey, VerifyingKey, curve

VECTORS = json.loads((Path(__file__).parent / "rfc8032_vectors.json").read_text())


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_rfc8032_vectors(vector: dict[str, str]) -> None:
    key = SigningKey(bytes.fromhex(vector["secret"]))
    message = bytes.fromhex(vector["message"])
    assert key.verifying_key.encoded.hex() == vector["public"]
    assert key.sign(message).hex() == vector["signature"]
    VerifyingKey(bytes.fromhex(vector["public"])).verify(
        bytes.fromhex(vector["signature"]), message
    )


def test_round_trip_and_tamper() -> None:
    key = SigningKey.generate()
    signature = key.sign(b"payload")
    key.verifying_key.verify(signature, b"payload")
    with pytest.raises(BadSignatureError):
        key.verifying_key.verify(signature, b"payloae")
    flipped = bytearray(signature)
    flipped[0] ^= 1
    with pytest.raises(BadSignatureError):
        key.verifying_key.verify(bytes(flipped), b"payload")
    with pytest.raises(BadSignatureError):
        SigningKey.generate().verifying_key.verify(signature, b"payload")


def test_signature_shape_is_checked() -> None:
    key = SigningKey(bytes(32))
    with pytest.raises(BadSignatureError, match="64 bytes"):
        key.verifying_key.verify(b"short", b"")
    with pytest.raises(BadSignatureError, match="64 bytes"):
        key.verifying_key.verify("x" * 64, b"")  # type: ignore[arg-type]


def test_malleable_s_is_refused() -> None:
    key = SigningKey(bytes(range(32)))
    signature = key.sign(b"m")
    s = int.from_bytes(signature[32:], "little") + curve.L
    with pytest.raises(BadSignatureError, match="group order"):
        key.verifying_key.verify(signature[:32] + s.to_bytes(32, "little"), b"m")


def test_key_arguments_are_checked() -> None:
    with pytest.raises(TypeError, match="must be bytes"):
        SigningKey("0" * 32)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="32 bytes, not 31"):
        SigningKey(bytes(31))
    with pytest.raises(ValueError, match="32 bytes"):
        VerifyingKey(bytes(33))
    non_canonical = (curve.P).to_bytes(32, "little")
    with pytest.raises(ValueError, match="point of the curve"):
        VerifyingKey(non_canonical)


def test_decode_refusals() -> None:
    assert curve.decode(bytes(31)) is None
    # y = 2 gives an x^2 with no square root.
    assert curve.decode((2).to_bytes(32, "little")) is None
    # y = 1 is the identity, with x = 0, so the sign bit cannot be set.
    assert curve.decode((1 | 1 << 255).to_bytes(32, "little")) is None
    assert curve.decode((1).to_bytes(32, "little")) == curve.IDENTITY


def test_group_laws() -> None:
    two_b = curve.double(curve.BASE)
    assert curve.encode(two_b) == curve.encode(curve.add(curve.BASE, curve.BASE))
    assert curve.encode(curve.multiply(curve.L, curve.BASE)) == curve.encode(curve.IDENTITY)
    assert curve.encode(curve.multiply_base(12345)) == curve.encode(
        curve.multiply(12345, curve.BASE)
    )
    for scalar in (1, 2, 3, 2**200 + 7):
        point = curve.multiply_base(scalar)
        decoded = curve.decode(curve.encode(point))
        assert decoded is not None
        assert curve.encode(decoded) == curve.encode(point)


def test_key_objects() -> None:
    key = SigningKey(bytes(32))
    assert key.seed == bytes(32)
    public = key.verifying_key
    assert public == VerifyingKey(public.encoded)
    assert public != object()
    assert hash(public) == hash(VerifyingKey(public.encoded))
    assert public.encoded.hex() in repr(public)
    assert "<secret>" in repr(key)
    assert bytes(32).hex() not in repr(key)


def test_matches_cryptography_when_installed() -> None:
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    raw = serialization.Encoding.Raw
    for seed in (bytes(32), bytes(range(32)), b"\xff" * 32):
        ours = SigningKey(seed)
        theirs = ed.Ed25519PrivateKey.from_private_bytes(seed)
        assert ours.verifying_key.encoded == theirs.public_key().public_bytes(
            raw, serialization.PublicFormat.Raw
        )
        assert ours.sign(b"abc") == theirs.sign(b"abc")
