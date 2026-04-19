import base64
import os
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates


def issue_pkcs12(sign_res: dict, private_key, p12_password: str) -> dict:
    cert = sign_res['cert']
    chain = sign_res['chain']

    encryption = (
        PrivateFormat.PKCS12.encryption_builder().
        kdf_rounds(50000).
        key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).
        hmac_hash(hashes.SHA1()).build(p12_password.encode('utf-8'))
    )

    out_pkcs12 = serialize_key_and_certificates(
        name=os.urandom(8).hex().encode('ascii'),
        key=private_key,
        cert=cert,
        cas=chain,
        encryption_algorithm=encryption
    )

    return {
        "metadata": {
            "issued_by": datetime.utcnow().isoformat(),
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat()
        },
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode('ascii'),
        "chain": [chain_cert.public_bytes(serialization.Encoding.PEM).decode('ascii') for chain_cert in chain],
        "private": {
            "pkcs12_b64": base64.b64encode(out_pkcs12).decode('ascii')
        }
    }
