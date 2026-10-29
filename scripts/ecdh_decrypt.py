#!/usr/bin/env python3
"""Decrypt an Enigma AES-GCM blob using the host side of ECDH + HKDF.

Requires: python3 -m pip install cryptography

The device public key must be exported from the EC key used for the ECDH
request. The salt must come from that same ECDH response. The ciphertext must
be encrypted with the resulting AES key ID; the label and ID are not HKDF
inputs. All public keys are SPKI, in PEM or DER form.
"""

import argparse
import base64
import binascii
import os
from pathlib import Path
import sys

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: install cryptography in your Python environment"
    ) from exc


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    data = path.read_bytes()
    if data.startswith(b"-----BEGIN "):
        key = serialization.load_pem_private_key(data, password=None)
    else:
        key = serialization.load_der_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("host private key must be an EC key")
    return key


def load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    data = path.read_bytes()
    if data.startswith(b"-----BEGIN "):
        key = serialization.load_pem_public_key(data)
    else:
        key = serialization.load_der_public_key(data)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("device public key must be an EC key")
    return key


def derive_aes_key(
    host_private: ec.EllipticCurvePrivateKey,
    device_public: ec.EllipticCurvePublicKey,
    salt: bytes,
    info: str,
) -> bytes:
    if host_private.curve.name != device_public.curve.name:
        raise ValueError("host and device EC keys use different curves")
    if len(salt) != 16:
        raise ValueError("Enigma ECDH salt must be 16 bytes")
    shared_secret = host_private.exchange(ec.ECDH(), device_public)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info.encode("utf-8"),
    ).derive(shared_secret)


def decrypt_blob(aes_key: bytes, blob: bytes) -> bytes:
    # Device wire format: nonce[12] || ciphertext || tag[16], with no AAD.
    if len(blob) < 29:
        raise ValueError("ciphertext must contain a nonce, data, and tag")
    return AESGCM(aes_key).decrypt(blob[:12], blob[12:], None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-private", type=Path, required=True)
    parser.add_argument("--device-public", type=Path, required=True)
    salt_group = parser.add_mutually_exclusive_group(required=True)
    salt_group.add_argument("--salt-file", type=Path, help="raw salt from ecdh --out-salt")
    salt_group.add_argument("--salt-hex", help="hex salt printed by ecdh")
    parser.add_argument(
        "--info",
        default="enigma/ecdh/aes256/v1",
        help="HKDF info from the ECDH response (default: current firmware value)",
    )
    ciphertext_group = parser.add_mutually_exclusive_group(required=True)
    ciphertext_group.add_argument("--ciphertext-file", type=Path, help="raw encrypt --out file")
    ciphertext_group.add_argument("--ciphertext-base64", help="base64 printed by encrypt")
    parser.add_argument("--output", type=Path, help="plaintext path; otherwise write raw bytes to stdout")
    args = parser.parse_args()

    try:
        salt = args.salt_file.read_bytes() if args.salt_file else bytes.fromhex(args.salt_hex)
        blob = (
            args.ciphertext_file.read_bytes()
            if args.ciphertext_file
            else base64.b64decode(args.ciphertext_base64, validate=True)
        )
        key = derive_aes_key(
            load_private_key(args.host_private),
            load_public_key(args.device_public),
            salt,
            args.info,
        )
        plaintext = decrypt_blob(key, blob)
        if args.output:
            # Plaintext may be sensitive; avoid overwriting an existing file.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(plaintext)
        else:
            sys.stdout.buffer.write(plaintext)
    except InvalidTag:
        parser.exit(1, "Decryption failed: authentication tag mismatch; check key pair, salt, info, and ciphertext.\n")
    except (OSError, ValueError, binascii.Error) as exc:
        parser.exit(1, f"Decryption failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
