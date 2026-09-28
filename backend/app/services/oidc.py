"""OIDC / OAuth2 access-token verification against a JWKS document.

Why this module exists
----------------------
Machine identities (sensors, integrations) already authenticate with hashed,
scoped API keys (see ``app.services.api_keys`` and ADR-0003). Human identities
were the missing half: the console held one shared server-side secret and any
bearer-shaped string was accepted as an administrator. This module verifies a
real OIDC access token instead, so a human caller carries a signed identity and
a role list issued by the identity provider.

No third-party JWT library is assumed
-------------------------------------
The environment this was developed in has **no** ``PyJWT``, ``python-jose`` and
no ``cryptography`` wheel installed, so the module is written against the
standard library only:

* ``cryptography`` is used **when importable** (``_load_cryptography()``) for
  RSA PKCS#1 v1.5 and ECDSA P-256 verification;
* otherwise the fallback path is used: RSA PKCS#1 v1.5 verification is done by
  parsing the JWK modulus/exponent and computing
  ``pow(signature, e, n)`` followed by an exact ``DigestInfo`` comparison, and
  ES256 verification is done with pure-Python P-256 point arithmetic
  (``_verify_es256_pure``). Both fallbacks are exercised by
  ``tests/test_oidc.py`` because ``cryptography`` is absent in the test
  environment.

That fallback is deliberately explicit rather than silently degraded: the same
checks (algorithm allow-list, ``kid`` binding, ``iss``/``aud``/``exp``/``nbf``/
``iat``) run on both paths, so the verified principal is identical.

Failure policy
--------------
Fail closed. ``verify_access_token`` returns ``None`` for every error - bad
structure, unknown ``kid`` that survives a JWKS refresh, algorithm confusion
(``alg: none`` and every HMAC algorithm are rejected outright, since the public
JWKS key would otherwise be usable as an HMAC secret), a signature that does not
check out, or a claim that does not match. There is no "default role" and no
implicit anonymous principal: a caller that cannot be verified simply has no
principal, and the authorization layer then denies the action.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

# ---------------------------------------------------------------- algorithms

# Only asymmetric signatures are acceptable. HMAC algorithms are rejected on
# purpose: the key needed to verify them is public, so accepting "HS256" would
# let anyone forge a token with the JWKS contents as the shared secret
# (algorithm-confusion attack). "none" is rejected for the obvious reason.
RSA_ALGORITHMS = {"RS256": "sha256", "RS384": "sha384", "RS512": "sha512"}
EC_ALGORITHMS = {"ES256": "sha256"}
SUPPORTED_ALGORITHMS = frozenset(RSA_ALGORITHMS) | frozenset(EC_ALGORITHMS)
REJECTED_HMAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
EC_CURVES = {"P-256": "ES256"}

# DigestInfo prefixes for PKCS#1 v1.5 (RFC 8017 section 9.2 notes).
_DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

DEFAULT_JWKS_TTL_SECONDS = 300
DEFAULT_LEEWAY_SECONDS = 60


class OidcError(RuntimeError):
    """Any verification failure. Never carries a partial/trusted principal."""


# ------------------------------------------------------------------ transport


class JwksTransport(Protocol):
    """Callable used to fetch a JWKS document.

    Injected so tests never touch the network; the default implementation is
    ``urllib_jwks_transport`` below.
    """

    def __call__(self, url: str) -> bytes:  # pragma: no cover - protocol
        ...


def urllib_jwks_transport(url: str, *, timeout: float = 5.0) -> bytes:
    """Default JWKS transport: a plain, short-timeout HTTPS GET.

    ``urllib`` is used instead of ``httpx``/``requests`` only because it needs no
    extra dependency; the timeout is deliberately short so an unreachable
    identity provider degrades to "verification failed" (fail closed) instead of
    hanging a request thread.
    """
    request = urllib.request.Request(url, headers={"accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured URL
            return bytes(response.read())
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise OidcError(f"JWKS fetch failed: {type(error).__name__}") from error


class JwksCache:
    """TTL cache for one JWKS document, with single-flight refresh on unknown kid.

    ``fetch_count`` is exposed for two reasons: operators can see how often the
    provider is polled, and the test suite asserts that an unknown ``kid``
    triggers exactly one refetch (not one per request, and not an unbounded
    number).
    """

    def __init__(
        self,
        url: str,
        *,
        transport: JwksTransport,
        ttl_seconds: int = DEFAULT_JWKS_TTL_SECONDS,
        clock: Any = time.monotonic,
    ) -> None:
        self.url = url
        self._transport = transport
        self._ttl_seconds = max(0, int(ttl_seconds))
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float | None = None
        self.fetch_count = 0

    @property
    def age_seconds(self) -> float | None:
        if self._fetched_at is None:
            return None
        return self._clock() - self._fetched_at

    def _is_fresh(self) -> bool:
        age = self.age_seconds
        return age is not None and age < self._ttl_seconds

    def get(self, kid: str, *, force_refresh: bool = False) -> dict[str, Any] | None:
        """Return the JWK for ``kid``, refreshing the document when needed."""
        with self._lock:
            fetched = False
            if force_refresh or not self._is_fresh():
                self._refresh_locked()
                fetched = True
            key = self._keys.get(kid)
            if key is None and not fetched:
                # Unknown kid on a still-fresh document: the provider probably
                # rotated its signing key. Refresh exactly once (never in a
                # loop) and give up if the kid is still absent - the caller then
                # fails closed instead of trusting an unselected key.
                self._refresh_locked()
                key = self._keys.get(kid)
            return key

    def _refresh_locked(self) -> None:
        raw = self._transport(self.url)
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OidcError("JWKS document is not valid JSON") from error
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list):
            raise OidcError("JWKS document has no 'keys' array")
        parsed: dict[str, dict[str, Any]] = {}
        for entry in keys:
            if not isinstance(entry, dict):
                continue
            kid = entry.get("kid")
            if isinstance(kid, str) and kid:
                parsed[kid] = entry
        self._keys = parsed
        self._fetched_at = self._clock()
        self.fetch_count += 1


# ------------------------------------------------------------------ principal


@dataclass(slots=True)
class OidcPrincipal:
    """Verified human identity derived from a signed access token."""

    subject: str
    display_name: str
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    workspace_id: str = "default"
    issuer: str = ""
    email: str | None = None
    expires_at: int | None = None
    claims: dict[str, Any] | None = None

    kind = "oidc"

    @property
    def display(self) -> str:
        """Audit identity: never client-supplied, always derived from the token."""
        return f"oidc:{self.subject}"

    @property
    def scope(self) -> str:
        """Primary scope, kept for code paths that only understand API-key scopes."""
        return self.roles[0] if self.roles else "viewer"


# ------------------------------------------------------------------- decoding


def b64url_decode(segment: str) -> bytes:
    """Decode an unpadded base64url segment (JWT/JWKS wire format)."""
    if not isinstance(segment, str) or not segment:
        raise OidcError("empty base64url segment")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as error:
        raise OidcError("invalid base64url segment") from error


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url (used by tests and tooling)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_json_segment(segment: str, label: str) -> dict[str, Any]:
    raw = b64url_decode(segment)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OidcError(f"JWT {label} is not valid JSON") from error
    if not isinstance(parsed, dict):
        raise OidcError(f"JWT {label} must be a JSON object")
    return parsed


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split and decode a compact JWS, returning header, payload, signing input.

    ``alg: none`` is rejected here rather than later, because an unsecured JWT has
    only two segments and must never be interpreted as a verified token.
    """
    if not isinstance(token, str):
        raise OidcError("token must be a string")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise OidcError("token must be a compact JWS with three segments")
    header = _decode_json_segment(parts[0], "header")
    payload = _decode_json_segment(parts[1], "payload")
    if not signature_bytes(parts[2]):
        raise OidcError("token has an empty signature")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return header, payload, signing_input, b64url_decode(parts[2])


def signature_bytes(segment: str) -> bytes:
    return b64url_decode(segment) if segment else b""


def looks_like_jwt(token: str) -> bool:
    """Cheap structural test used to route a bearer credential.

    A database API key never contains two dots, so this only ever selects the
    OIDC path for something that claims to be a JWT; verification still decides
    whether it is trusted.
    """
    if not isinstance(token, str):
        return False
    parts = token.strip().split(".")
    if len(parts) != 3 or len(token) > 8192:
        return False
    return all(parts)


# -------------------------------------------------------------------- crypto


def _load_cryptography() -> Any | None:
    """Return the ``cryptography`` module when it is installed, else ``None``."""
    try:  # pragma: no cover - depends on the environment
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
    except Exception:  # noqa: BLE001 - import environment is not our concern
        return None
    return {
        "rsa": rsa,
        "ec": ec,
        "padding": padding,
        "hashes": hashes,
        "InvalidSignature": InvalidSignature,
    }


def _rsa_public_numbers(jwk: dict[str, Any]) -> tuple[int, int]:
    try:
        modulus = int.from_bytes(b64url_decode(str(jwk["n"])), "big")
        exponent = int.from_bytes(b64url_decode(str(jwk["e"])), "big")
    except (KeyError, OidcError) as error:
        raise OidcError("RSA JWK is missing 'n' or 'e'") from error
    if modulus <= 0 or exponent <= 0:
        raise OidcError("RSA JWK modulus/exponent must be positive")
    return modulus, exponent


def _verify_rsa_pure(jwk: dict[str, Any], signing_input: bytes, signature: bytes, digest: str) -> None:
    """RSA PKCS#1 v1.5 verification with no crypto dependency.

    This is the path actually exercised in this repository's test environment
    (``cryptography`` is not installed there). It is textbook RSA verification:
    ``m = s^e mod n``, then an exact comparison against the DigestInfo-prefixed
    ``EM`` structure required by RFC 8017 section 9.2. No unpadding heuristics
    and no prefix match - a mismatch is a failure.
    """
    modulus, exponent = _rsa_public_numbers(jwk)
    modulus_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) != modulus_bytes:
        raise OidcError("RSA signature length does not match the key modulus")
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        raise OidcError("RSA signature is not smaller than the modulus")
    try:
        recovered = pow(signature_int, exponent, modulus).to_bytes(modulus_bytes, "big")
    except ValueError as error:  # pragma: no cover - int.to_bytes overflow guard
        raise OidcError("RSA verification failed") from error
    digest_bytes = hashlib.new(digest, signing_input).digest()
    expected_tail = _DIGEST_INFO_PREFIX[digest] + digest_bytes
    padding_length = modulus_bytes - len(expected_tail) - 3
    if padding_length < 8:
        raise OidcError("RSA key is too small for the requested digest")
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + expected_tail
    if recovered != expected:
        raise OidcError("RSA signature verification failed")


def _verify_es256_pure(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    """ECDSA P-256 (ES256) verification with pure-Python point arithmetic.

    Used only when ``cryptography`` is unavailable. Supports the JWS raw
    ``r || s`` signature form and also accepts a DER-encoded signature, which
    some providers emit. All arithmetic is on integers, so there is no timing
    dependency on secret material - ECDSA verification uses public values only.
    """
    if len(signature) == 64:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    else:
        r, s = _decode_der_signature(signature)
    if not (0 < r < _P256_N and 0 < s < _P256_N):
        raise OidcError("ES256 signature values are out of range")
    digest = hashlib.sha256(signing_input).digest()
    z = int.from_bytes(digest, "big")
    try:
        x, y = _p256_jwk_point(jwk)
    except OidcError:
        raise
    w = pow(s, -1, _P256_N)
    u1 = (z * w) % _P256_N
    u2 = (r * w) % _P256_N
    point = _p256_add(_p256_mul(u1, _P256_G), _p256_mul(u2, (x, y)))
    if point is None:
        raise OidcError("ES256 signature verification failed")
    if point[0] % _P256_N != r:
        raise OidcError("ES256 signature verification failed")


def _decode_der_signature(signature: bytes) -> tuple[int, int]:
    if len(signature) < 8 or signature[0] != 0x30:
        raise OidcError("ES256 signature is neither raw r||s nor DER")
    index = 2 if signature[1] < 0x80 else 2 + (signature[1] & 0x7F)
    try:
        if signature[index] != 0x02:
            raise OidcError("ES256 DER signature has no r integer")
        r_length = signature[index + 1]
        r = int.from_bytes(signature[index + 2 : index + 2 + r_length], "big")
        cursor = index + 2 + r_length
        if signature[cursor] != 0x02:
            raise OidcError("ES256 DER signature has no s integer")
        s_length = signature[cursor + 1]
        s = int.from_bytes(signature[cursor + 2 : cursor + 2 + s_length], "big")
    except IndexError as error:
        raise OidcError("ES256 DER signature is truncated") from error
    return r, s


# NIST P-256 (secp256r1) domain parameters.
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _p256_jwk_point(jwk: dict[str, Any]) -> tuple[int, int]:
    curve = jwk.get("crv")
    if curve not in EC_CURVES:
        raise OidcError(f"unsupported EC curve {curve!r}")
    try:
        x = int.from_bytes(b64url_decode(str(jwk["x"])), "big")
        y = int.from_bytes(b64url_decode(str(jwk["y"])), "big")
    except (KeyError, OidcError) as error:
        raise OidcError("EC JWK is missing 'x' or 'y'") from error
    if not (0 <= x < _P256_P and 0 <= y < _P256_P):
        raise OidcError("EC public point is outside the field")
    if (y * y - (pow(x, 3, _P256_P) + _P256_A * x + _P256_B)) % _P256_P != 0:
        raise OidcError("EC public point is not on the P-256 curve")
    return x, y


def _p256_inverse(value: int) -> int:
    return pow(value, -1, _P256_P)


def _p256_add(
    first: tuple[int, int] | None, second: tuple[int, int] | None
) -> tuple[int, int] | None:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if first == second:
        slope = (3 * x1 * x1 + _P256_A) * _p256_inverse(2 * y1 % _P256_P) % _P256_P
    else:
        slope = (y2 - y1) * _p256_inverse((x2 - x1) % _P256_P) % _P256_P
    x3 = (slope * slope - x1 - x2) % _P256_P
    y3 = (slope * (x1 - x3) - y1) % _P256_P
    return x3, y3


def _p256_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        scalar >>= 1
    return result


def verify_rsa_signature(
    jwk: dict[str, Any], signing_input: bytes, signature: bytes, digest: str
) -> None:
    """RSA PKCS#1 v1.5 verification; prefers ``cryptography`` when available."""
    crypto = _load_cryptography()
    if crypto is None:
        _verify_rsa_pure(jwk, signing_input, signature, digest)
        return
    modulus, exponent = _rsa_public_numbers(jwk)
    try:
        public_key = crypto["rsa"].RSAPublicNumbers(exponent, modulus).public_key()
        public_key.verify(
            signature,
            signing_input,
            crypto["padding"].PKCS1v15(),
            getattr(crypto["hashes"], digest.upper())(),
        )
    except crypto["InvalidSignature"] as error:
        raise OidcError("RSA signature verification failed") from error
    except Exception as error:  # noqa: BLE001 - malformed key material
        raise OidcError(f"RSA verification error: {type(error).__name__}") from error


def verify_es256_signature(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    """ECDSA P-256 verification; prefers ``cryptography`` when available."""
    crypto = _load_cryptography()
    if crypto is None:
        _verify_es256_pure(jwk, signing_input, signature)
        return
    x, y = _p256_jwk_point(jwk)
    try:
        public_key = crypto["ec"].EllipticCurvePublicNumbers(
            x, y, crypto["ec"].SECP256R1()
        ).public_key()
        public_key.verify(signature, signing_input, crypto["ec"].ECDSA(crypto["hashes"].SHA256()))
    except crypto["InvalidSignature"] as error:
        raise OidcError("ES256 signature verification failed") from error
    except Exception as error:  # noqa: BLE001 - malformed key material
        raise OidcError(f"ES256 verification error: {type(error).__name__}") from error


def verify_signature(jwk: dict[str, Any], alg: str, signing_input: bytes, signature: bytes) -> None:
    """Verify a JWS signature against one JWK, rejecting unusable key material."""
    kty = jwk.get("kty")
    if alg in REJECTED_HMAC_ALGORITHMS or alg == "none":
        raise OidcError(f"algorithm {alg!r} is not accepted")
    if alg in RSA_ALGORITHMS:
        if kty != "RSA":
            raise OidcError(f"algorithm {alg} requires an RSA key, got {kty!r}")
        _check_key_usable(jwk)
        verify_rsa_signature(jwk, signing_input, signature, RSA_ALGORITHMS[alg])
        return
    if alg in EC_ALGORITHMS:
        if kty != "EC":
            raise OidcError(f"algorithm {alg} requires an EC key, got {kty!r}")
        if jwk.get("crv") != "P-256":
            raise OidcError(f"algorithm {alg} requires curve P-256, got {jwk.get('crv')!r}")
        _check_key_usable(jwk)
        verify_es256_signature(jwk, signing_input, signature)
        return
    raise OidcError(f"unsupported algorithm {alg!r}")


def _check_key_usable(jwk: dict[str, Any]) -> None:
    """Refuse a key the provider marked as encryption-only."""
    if jwk.get("use") == "enc":
        raise OidcError("JWK is marked for encryption, not signature verification")
    key_ops = jwk.get("key_ops")
    if isinstance(key_ops, list) and key_ops and "verify" not in key_ops:
        raise OidcError("JWK key_ops does not allow signature verification")


# -------------------------------------------------------------------- claims


def _claim_path(claims: dict[str, Any], path: str) -> Any:
    """Read a possibly dotted claim path, e.g. ``realm_access.roles``."""
    current: Any = claims
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item for item in value.replace(",", " ").split() if item]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item) for item in value if isinstance(item, (str, int, float)) and str(item)]
    return []


def extract_roles(claims: dict[str, Any], roles_claims: Sequence[str]) -> list[str]:
    """Collect role names from every configured claim path.

    Defaults cover the two common shapes: Azure AD / Auth0 style ``roles`` and
    Keycloak's nested ``realm_access.roles``. Order is preserved and duplicates
    are dropped so the resulting list is deterministic for audit records.
    """
    roles: list[str] = []
    for path in roles_claims:
        for role in _string_list(_claim_path(claims, path)):
            if role not in roles:
                roles.append(role)
    return roles


def extract_scopes(claims: dict[str, Any]) -> list[str]:
    """Read OAuth2 scopes from ``scope`` (space separated) or ``scp`` (list)."""
    scopes: list[str] = []
    for path in ("scope", "scp", "scopes"):
        for scope in _string_list(_claim_path(claims, path)):
            if scope not in scopes:
                scopes.append(scope)
    return scopes


def _audience_matches(audience: Any, expected: Sequence[str]) -> bool:
    if not expected:
        return True
    if isinstance(audience, str):
        return audience in expected
    if isinstance(audience, Sequence) and not isinstance(audience, (bytes, bytearray)):
        return any(str(item) in expected for item in audience)
    return False


def validate_claims(
    claims: dict[str, Any],
    *,
    issuer: str,
    audiences: Sequence[str],
    leeway_seconds: int,
    now: float,
    require_exp: bool = True,
) -> None:
    """Validate ``iss``/``aud``/``exp``/``nbf``/``iat``; raise ``OidcError`` otherwise."""
    if issuer:
        if str(claims.get("iss", "")) != issuer:
            raise OidcError("token issuer does not match the configured issuer")
    if audiences:
        if not _audience_matches(claims.get("aud"), audiences):
            raise OidcError("token audience does not match the configured audience")

    grace = max(0, int(leeway_seconds))
    expires_at = claims.get("exp")
    if expires_at is None:
        if require_exp:
            raise OidcError("token has no 'exp' claim")
    else:
        try:
            expires_value = float(expires_at)
        except (TypeError, ValueError) as error:
            raise OidcError("token 'exp' claim is not numeric") from error
        if expires_value + grace < now:
            raise OidcError("token has expired")

    not_before = claims.get("nbf")
    if not_before is not None:
        try:
            not_before_value = float(not_before)
        except (TypeError, ValueError) as error:
            raise OidcError("token 'nbf' claim is not numeric") from error
        if not_before_value - grace > now:
            raise OidcError("token is not valid yet")

    issued_at = claims.get("iat")
    if issued_at is not None:
        try:
            issued_value = float(issued_at)
        except (TypeError, ValueError) as error:
            raise OidcError("token 'iat' claim is not numeric") from error
        # An iat far in the future is a claim-integrity problem even when exp is
        # valid, so it is rejected with the same leeway as nbf.
        if issued_value - grace > now:
            raise OidcError("token 'iat' claim is in the future")


def _subject_of(claims: dict[str, Any]) -> str:
    subject = claims.get("sub")
    if isinstance(subject, str) and subject.strip():
        return subject.strip()
    raise OidcError("token has no usable 'sub' claim")


def _display_name_of(claims: dict[str, Any], subject: str) -> str:
    for path in ("preferred_username", "email", "name", "upn"):
        value = _claim_path(claims, path)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return subject


# ------------------------------------------------------------------ verifier


@dataclass(slots=True)
class OidcConfig:
    """Everything the verifier needs; built from ``app.core.config.Settings``."""

    issuer: str = ""
    audience: str = ""
    jwks_url: str = ""
    roles_claims: tuple[str, ...] = ("roles", "realm_access.roles")
    role_scope_map: dict[str, list[str]] | None = None
    workspace_claim: str = "workspace"
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS
    jwks_ttl_seconds: int = DEFAULT_JWKS_TTL_SECONDS
    default_workspace: str = "default"
    algorithms: tuple[str, ...] = tuple(sorted(SUPPORTED_ALGORITHMS))

    @property
    def audiences(self) -> list[str]:
        return [item.strip() for item in str(self.audience).split(",") if item.strip()]


class OidcVerifier:
    """Verifies access tokens against a JWKS document and maps claims to a principal."""

    def __init__(
        self,
        config: OidcConfig,
        *,
        transport: JwksTransport | None = None,
        clock: Any = time.time,
        monotonic: Any = time.monotonic,
    ) -> None:
        self.config = config
        self._clock = clock
        self._jwks = JwksCache(
            config.jwks_url,
            transport=transport or urllib_jwks_transport,
            ttl_seconds=config.jwks_ttl_seconds,
            clock=monotonic,
        )

    @property
    def jwks_fetch_count(self) -> int:
        return self._jwks.fetch_count

    def verify_access_token(self, token: str, *, now: float | None = None) -> OidcPrincipal | None:
        """Return the verified principal, or ``None`` when anything does not check out.

        Fail-closed by construction: every failure path returns ``None`` and the
        caller must treat that as "no identity", never as a default role.
        """
        try:
            return self._verify(token, now=self._clock() if now is None else now)
        except OidcError:
            return None

    def _verify(self, token: str, *, now: float) -> OidcPrincipal:
        header, claims, signing_input, signature = decode_jwt(token)
        alg = header.get("alg")
        if not isinstance(alg, str) or not alg:
            raise OidcError("JWT header has no 'alg'")
        if alg.lower() == "none" or alg in REJECTED_HMAC_ALGORITHMS:
            raise OidcError(f"algorithm {alg!r} is refused")
        if alg not in self.config.algorithms:
            raise OidcError(f"algorithm {alg!r} is not enabled")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OidcError("JWT header has no 'kid'; key selection would be ambiguous")
        jwk = self._jwks.get(kid)
        if jwk is None:
            raise OidcError(f"no JWKS entry for kid {kid!r} after refresh")
        verify_signature(jwk, alg, signing_input, signature)
        validate_claims(
            claims,
            issuer=self.config.issuer,
            audiences=self.config.audiences,
            leeway_seconds=self.config.leeway_seconds,
            now=now,
        )
        return self._principal_from_claims(claims)

    def _principal_from_claims(self, claims: dict[str, Any]) -> OidcPrincipal:
        subject = _subject_of(claims)
        roles = extract_roles(claims, self.config.roles_claims)
        scopes = extract_scopes(claims)
        mapped = self.map_roles_to_scopes(roles)
        for scope in mapped:
            if scope not in scopes:
                scopes.append(scope)
        workspace = _claim_path(claims, self.config.workspace_claim)
        workspace_id = workspace.strip() if isinstance(workspace, str) and workspace.strip() else ""
        expires_at = claims.get("exp")
        return OidcPrincipal(
            subject=subject,
            display_name=_display_name_of(claims, subject),
            roles=roles,
            scopes=scopes,
            workspace_id=workspace_id or self.config.default_workspace,
            issuer=str(claims.get("iss", "")),
            email=claims.get("email") if isinstance(claims.get("email"), str) else None,
            expires_at=int(expires_at) if isinstance(expires_at, (int, float)) else None,
            claims={
                "iss": str(claims.get("iss", "")),
                "aud": claims.get("aud"),
                "roles": list(roles),
                "scopes": list(scopes),
            },
        )

    def map_roles_to_scopes(self, roles: Sequence[str]) -> list[str]:
        """Translate provider role names into EvoNIDS scopes via the configured map.

        An unmapped role contributes nothing. The mapping is data, not code, so a
        provider that renames a role fails closed (the role simply stops granting
        anything) instead of silently keeping permissions.
        """
        mapping = self.config.role_scope_map or {}
        scopes: list[str] = []
        for role in roles:
            for scope in mapping.get(role, []):
                if scope not in scopes:
                    scopes.append(scope)
        return scopes


_VERIFIER: OidcVerifier | None = None
_VERIFIER_LOCK = threading.Lock()


def build_verifier_from_settings(settings: Any) -> OidcVerifier:
    """Build a verifier from ``app.core.config.Settings``."""
    mapping = getattr(settings, "oidc_role_scopes", None) or {}
    roles_claims = getattr(settings, "oidc_roles_claim", None) or "roles,realm_access.roles"
    return OidcVerifier(
        OidcConfig(
            issuer=str(getattr(settings, "oidc_issuer", "") or ""),
            audience=str(getattr(settings, "oidc_audience", "") or ""),
            jwks_url=str(getattr(settings, "oidc_jwks_url", "") or ""),
            roles_claims=tuple(
                item.strip() for item in str(roles_claims).split(",") if item.strip()
            ),
            role_scope_map={str(key): list(value) for key, value in dict(mapping).items()},
            workspace_claim=str(getattr(settings, "oidc_workspace_claim", "workspace") or "workspace"),
            leeway_seconds=int(getattr(settings, "oidc_leeway_seconds", DEFAULT_LEEWAY_SECONDS) or 0),
            default_workspace=str(getattr(settings, "default_workspace", "default") or "default"),
        )
    )


def get_verifier(settings: Any = None) -> OidcVerifier | None:
    """Process-cached verifier for the current settings, or ``None`` when disabled.

    Caching matters because the JWKS cache lives inside the verifier: rebuilding
    it per request would refetch the provider every time.
    """
    global _VERIFIER
    if settings is None:
        from app.core.config import get_settings

        settings = get_settings()
    if not getattr(settings, "oidc_enabled", False):
        return None
    with _VERIFIER_LOCK:
        if _VERIFIER is None:
            _VERIFIER = build_verifier_from_settings(settings)
        return _VERIFIER


def reset_verifier() -> None:
    """Drop the cached verifier (used by tests and after a settings change)."""
    global _VERIFIER
    with _VERIFIER_LOCK:
        _VERIFIER = None


def verify_bearer_token(token: str, *, settings: Any = None) -> OidcPrincipal | None:
    """Convenience entry point used by ``app.api.security``."""
    verifier = get_verifier(settings)
    if verifier is None:
        return None
    return verifier.verify_access_token(token)
