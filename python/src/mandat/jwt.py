"""JWS/JWT verification (RFC 7515/7519) for asymmetric algorithms only: ES256, RS256, PS256, EdDSA.

"none" and HMAC are rejected so a public key can never be abused as a shared secret. Port of src/sts/jwt.ts.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import urllib.request
from typing import Any, Awaitable, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

__all__ = ["JwtError", "decode_jwt", "verify_jwt", "jwk_to_key", "JwksClient"]

ALGS = ("ES256", "RS256", "PS256", "EdDSA")
PublicKey = ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey
KeyResolver = Callable[[dict[str, Any], dict[str, Any]], "Awaitable[PublicKey | None] | PublicKey | None"]


class JwtError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Returns (header, payload, signing_input, signature) without verifying anything."""
    if not isinstance(token, str) or len(token) > 16_384:
        raise JwtError("malformed", "Token missing or too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("malformed", "Token is not a compact JWS")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
    except Exception as e:  # noqa: BLE001
        raise JwtError("malformed", "Token segments are not valid base64url JSON") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtError("malformed", "Token header and payload must be JSON objects")
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), signature


def _key_matches(key: Any, alg: str) -> bool:
    if alg == "ES256":
        return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
    if alg in ("RS256", "PS256"):
        return isinstance(key, rsa.RSAPublicKey)
    return isinstance(key, ed25519.Ed25519PublicKey)


def _verify_signature(key: Any, alg: str, data: bytes, sig: bytes) -> bool:
    try:
        if alg == "ES256":
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        elif alg == "RS256":
            key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "PS256":
            key.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        else:
            key.verify(sig, data)
        return True
    except InvalidSignature:
        return False


async def verify_jwt(
    token: str,
    resolve_key: KeyResolver,
    *,
    issuer: str | list[str] | None = None,
    audience: str | list[str] | None = None,
    typ: str | None = None,
    require_exp: bool = True,
    clock_tolerance: int = 30,
) -> dict[str, Any]:
    header, payload, signing_input, signature = decode_jwt(token)
    alg = header.get("alg")
    if alg not in ALGS:
        raise JwtError("bad_alg", f"Algorithm '{alg}' is not allowed")
    if typ and header.get("typ") and str(header["typ"]).lower() != typ.lower():
        raise JwtError("bad_typ", f"Unexpected token type '{header['typ']}'")
    key = resolve_key(header, payload)
    if asyncio.iscoroutine(key) or isinstance(key, asyncio.Future):
        key = await key
    if key is None:
        raise JwtError("unknown_key", f"No key for kid '{header.get('kid', '(none)')}'")
    if not _key_matches(key, alg):
        raise JwtError("bad_alg", "Key type does not match algorithm")
    if not _verify_signature(key, alg, signing_input, signature):
        raise JwtError("bad_signature", "Signature verification failed")

    now = int(time.time())
    exp, nbf = payload.get("exp"), payload.get("nbf")
    if exp is None and require_exp:
        raise JwtError("no_exp", "Token has no exp")
    if isinstance(exp, (int, float)) and now > exp + clock_tolerance:
        raise JwtError("expired", "Token expired")
    if isinstance(nbf, (int, float)) and now + clock_tolerance < nbf:
        raise JwtError("not_yet_valid", "Token not yet valid")
    if issuer:
        allowed = issuer if isinstance(issuer, list) else [issuer]
        if payload.get("iss") not in allowed:
            raise JwtError("bad_iss", f"Unexpected issuer '{payload.get('iss')}'")
    if audience:
        want = audience if isinstance(audience, list) else [audience]
        aud = payload.get("aud")
        got = aud if isinstance(aud, list) else [aud] if aud else []
        if not any(a in want for a in got):
            raise JwtError("bad_aud", f"Token audience {json.dumps(aud)} is not for this resource")
    return payload


def jwk_to_key(jwk: dict[str, Any]) -> PublicKey:
    kty = jwk.get("kty")
    if kty == "EC":
        if jwk.get("crv") != "P-256":
            raise ValueError(f"Unsupported curve {jwk.get('crv')}")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
    raise ValueError(f"Unsupported key type {kty}")


class JwksClient:
    """Caches a remote JWKS; refetches on an unknown kid at most once per `min_refresh` seconds."""

    def __init__(self, url: str, ttl: float = 600, min_refresh: float = 30) -> None:
        self.url = url
        self.ttl = ttl
        self.min_refresh = min_refresh
        self._keys: dict[str, PublicKey] = {}
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str | None) -> PublicKey | None:
        age = time.monotonic() - self._fetched_at
        if age > self.ttl or (kid and kid not in self._keys and age > self.min_refresh) or not self._fetched_at:
            async with self._lock:
                if time.monotonic() - self._fetched_at > 1:  # another waiter may have refreshed already
                    try:
                        await asyncio.to_thread(self._refresh)
                    except Exception:
                        # An outage must not reject tokens the cached keys can still check: retry later instead.
                        if not self._keys:
                            raise
                        self._fetched_at = time.monotonic() - self.ttl + self.min_refresh
        if kid:
            return self._keys.get(kid)
        return next(iter(self._keys.values())) if len(self._keys) == 1 else None

    def _refresh(self) -> None:
        with urllib.request.urlopen(self.url, timeout=5) as res:  # noqa: S310 - URL comes from configuration
            body = json.loads(res.read())
        keys: dict[str, PublicKey] = {}
        for jwk in body.get("keys", []):
            if jwk.get("use") not in (None, "sig"):
                continue
            try:
                keys[jwk.get("kid") or ""] = jwk_to_key(jwk)
            except ValueError:
                continue
        self._keys = keys
        self._fetched_at = time.monotonic()
