import binascii
import tempfile

import httpx
from aiocache import cached
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding

from ..config import PUBLIC_PROXY_CACHE_INTERVAL, TINYPKI_STEP_CA_URL, TINYPKI_STEP_CA_ROOT_FINGERPRINT


@cached(ttl=PUBLIC_PROXY_CACHE_INTERVAL)
async def get_step_ca_verify():
    # get the value for the httpx.request(..., verify=...)

    if not TINYPKI_STEP_CA_ROOT_FINGERPRINT:
        # fingerprint verification is disabled
        return False

    async with httpx.AsyncClient(verify=False) as client:
        url = f'{TINYPKI_STEP_CA_URL}/root/{TINYPKI_STEP_CA_ROOT_FINGERPRINT}'
        req = client.build_request("GET", url)
        res = await client.send(req, stream=True)
        await res.aread()
        res.raise_for_status()
        ca_pem = res.json()['ca']

    cert: x509.Certificate = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
    cert_fingerprint = cert.fingerprint(hashes.SHA256())
    want_fingerprint = binascii.unhexlify(TINYPKI_STEP_CA_ROOT_FINGERPRINT)

    if cert_fingerprint != want_fingerprint:
        raise RuntimeError("Mismatched Step CA fingerprint."
                           f"  Expected: {want_fingerprint.hex()}"
                           f"  Actual: {cert_fingerprint.hex()}")

    tempf = tempfile.NamedTemporaryFile("wb", delete=False, prefix="step_ca_root_")
    tempf.write(cert.public_bytes(Encoding.PEM))
    tempf.close()

    return tempf.name
