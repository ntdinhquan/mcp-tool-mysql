import hashlib
import hmac
import secrets
from dataclasses import dataclass

TOKEN_PREFIX = "cpm"


@dataclass(frozen=True)
class GeneratedToken:
    plaintext: str
    prefix: str
    token_hash: str


@dataclass(frozen=True)
class Principal:
    """Identity of an authenticated token, with the tables it may read right now."""

    token_id: str
    name: str
    organization_name: str
    tables: frozenset[str]


def hash_token(plaintext: str) -> str:
    # The secret is 256 bits of randomness, so a plain SHA-256 is enough (no need for a slow KDF).
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def generate_token() -> GeneratedToken:
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    plaintext = f"{TOKEN_PREFIX}_{prefix}_{secret}"
    return GeneratedToken(plaintext=plaintext, prefix=prefix, token_hash=hash_token(plaintext))


def parse_prefix(plaintext: str) -> str | None:
    """Extract the lookup prefix from `cpm_<prefix>_<secret>`; None when malformed."""
    parts = plaintext.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[1] or not parts[2]:
        return None
    return parts[1]


def verify_token(plaintext: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(plaintext), stored_hash)
