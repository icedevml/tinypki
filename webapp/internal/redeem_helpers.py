import base64
import hashlib
import random

from ..config import PBKDF2_SALT, PBKDF2_ITERATIONS

# the charset is stripped off potentially ambiguous characters
# to increase success rate for users with dyslexia and where their native charset is non-latin

# without '0', '1', '2', '5'
cdkey_digits = '346789'
# without 'I', 'O', 'S'
cdkey_letters = "ABCDEFGHJKLMNPQRTUVWXYZ"


def _secure_random_segment(length: int):
    return ''.join(random.SystemRandom().choice(cdkey_digits + cdkey_letters) for _ in range(length))


# generate a 4x4 cd-key alike redeem code (total domain: 29^16 ~= 77 bits of security)
# should be fairly reasonable to protect against online brute force, especially when also involving rate limits
def make_redeem_code() -> str:
    return '-'.join([_secure_random_segment(4) for _ in range(5)])


def hash_redeem_code(redeem_code: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=redeem_code.encode("ascii"),
            salt=PBKDF2_SALT,
            iterations=PBKDF2_ITERATIONS
        )
    ).decode("ascii")


def make_pkcs12_password(*, length: int):
    return ''.join(random.SystemRandom().choice(cdkey_digits + cdkey_letters.lower()) for _ in range(length))
