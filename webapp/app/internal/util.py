import base64
import os


def make_submit_nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)) \
        .decode("ascii") \
        .replace("=", "")
