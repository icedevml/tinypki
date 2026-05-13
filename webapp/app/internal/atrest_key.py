import base64
import hashlib

from jwcrypto import jwk

from ..config import PBKDF2_ITERATIONS, PBKDF2_SALT, ATREST_ENCRYPTION_KEY


def create_atrest_jwk() -> jwk.JWK:
    key = jwk.JWK.from_password(ATREST_ENCRYPTION_KEY)
    digest = hashlib.pbkdf2_hmac("sha256", key["k"].encode("ascii"), PBKDF2_SALT, PBKDF2_ITERATIONS)[0:16]
    kid = base64.urlsafe_b64encode(digest).replace(b"=", b"").decode("ascii")
    key["kid"] = kid
    return key
