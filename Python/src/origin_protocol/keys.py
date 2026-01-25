from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


@dataclass(frozen=True)
class KeyMetadata:
    key_id: str
    created_at: str
    algorithm: str = "ed25519"
    origin_schema: str = "1.0"


def generate_keypair() -> KeyPair:
    private_key = Ed25519PrivateKey.generate()
    return KeyPair(private_key=private_key, public_key=private_key.public_key())


def canonical_key_id(public_key: Ed25519PublicKey) -> str:
    return public_key_fingerprint(public_key)


def build_key_metadata(public_key: Ed25519PublicKey) -> KeyMetadata:
    return KeyMetadata(
        key_id=canonical_key_id(public_key),
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def save_keypair(keypair: KeyPair, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "private_key.ed25519"
    public_path = directory / "public_key.ed25519"

    private_bytes = keypair.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = keypair.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)

    return private_path, public_path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Unsupported private key type")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Unsupported public key type")
    return key


def load_public_key_bytes(data: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Unsupported public key type")
    return key


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def validate_public_key_pem(pem: str) -> bool:
    """Validate that a PEM string is a valid Ed25519 public key.
    
    Args:
        pem: PEM-formatted public key string
        
    Returns:
        True if valid, False otherwise
    """
    try:
        serialization.load_pem_public_key(pem.encode("utf-8"))
        return True
    except (ValueError, TypeError):
        # ValueError: Invalid PEM format
        # TypeError: Invalid input type
        return False


def export_raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
