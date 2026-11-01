# pyrixos-ed25519

Ed25519 signatures, as RFC 8032 section 5.1 defines them, in Python with
no compiled code and no dependencies. PyrixOS uses it to sign and check
its binary cache, so its build tools need no Rust or C extension.

```sh
pip install pyrixos-ed25519
```

```python
from pyrixos_ed25519 import BadSignatureError, SigningKey, VerifyingKey

key = SigningKey.generate()            # or SigningKey(seed), 32 bytes
signature = key.sign(b"message")       # 64 bytes
public = key.verifying_key.encoded     # 32 bytes

try:
    VerifyingKey(public).verify(signature, b"message")
except BadSignatureError:
    ...
```

Keys and signatures are the raw byte strings of RFC 8032, so they
interoperate with OpenSSL, libsodium and the `cryptography` package.
The tests check the RFC's vectors and, when `cryptography` is
installed, compare signatures with it.

## Verification rules

`verify` refuses a signature whose S is not less than the group order,
and a public key or R that is not a canonical encoding of a curve
point. It checks `[S]B - [k]A` against R without multiplying by the
cofactor, the rule OpenSSL and libsodium follow.

## Limits

Python integers give no constant-time arithmetic, so signing time
depends on the secret key. Use the package where an attacker cannot
time many signatures, such as signing build outputs on a build host.
Signing takes about 2 ms and verification about 10 ms
on a current x86_64 core.

## Development

```sh
pip install --group dev
pip install -e .
pybootstrap check
```

## License

GPL-2.0-only. See [LICENSE](LICENSE).
