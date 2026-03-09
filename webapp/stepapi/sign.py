import uuid
from datetime import timezone, datetime, timedelta

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import load_pem_x509_csr
from jwt.algorithms import ECAlgorithm

from .ca_fingerprint import get_step_ca_verify
from ..config import TINYPKI_STEP_CA_URL, TINYPKI_DISALLOWED_NAMES
from ..internal.exc import InvalidCSR
from ..internal.key_spec import KeySpec
from ..internal.san_utils import map_san, unmap_sans


class StepSignError(RuntimeError):
    pass


class CSR:
    def __init__(self, cn: str, sans: list):
        self.cn = cn
        self.sans = sans

        self.csr_pem_bytes = None
        self.private_key = None

    @staticmethod
    def from_pem(data: str, *, required_cn: str, required_sans: list[str], required_key_algorithm: str):
        obj = load_pem_x509_csr(data.encode("ascii"))

        # verify whether the CSR conforms with the key spec
        key_spec = KeySpec.from_string(required_key_algorithm)
        key_spec.verify_csr(obj)

        # extract CN/SANS
        cn_arr = obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

        if not cn_arr or len(cn_arr) != 1 or not cn_arr[0].value:
            raise InvalidCSR("Expected a single Subject Common Name attribute with a non-empty value.")

        cn = cn_arr[0].value
        sans = unmap_sans(obj)

        # verify CN/SANS match with what we expect
        if not required_cn or required_cn != cn:
            raise InvalidCSR("The CSR doesn't contain the expected Common Name.")

        if set(required_sans) != set(sans):
            raise InvalidCSR("The CSR doesn't contain the expected set of Subject Alternative Names.")

        # create CSR
        out = CSR(cn=cn, sans=sans)
        # re-serialize to reduce the likehood for any quirks
        out.csr_pem_bytes = obj.public_bytes(Encoding.PEM)
        # not available/not needed for user-imported CSRs
        out.key = None
        return out

    def generate(self, key_spec: KeySpec):
        private_key = key_spec.generate_private_key()

        pyca_csr = x509.CertificateSigningRequestBuilder(
        ).subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.cn)])
        ).add_extension(
            x509.SubjectAlternativeName(
                [map_san(san) for san in self.sans]
            ),
            critical=False,
        ).sign(private_key, key_spec.create_hash_instance())

        key_spec.verify_csr(pyca_csr)

        self.csr_pem_bytes = pyca_csr.public_bytes(serialization.Encoding.PEM)
        self.private_key = private_key

    # Returns an encrypted PEM of the private key
    def key_pem(self, passphrase):
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes(passphrase, 'UTF-8')),
        )


async def sign_cert(
        *,
        provisioner: dict,
        csr_pem: str,
        cn: str,
        sans: list[str],
        not_before: str,
        not_after: str,
        template_data: dict
) -> dict:
    sans_vals = [v.partition(":")[2] for v in sans]

    if cn in TINYPKI_DISALLOWED_NAMES:
        raise RuntimeError("Refusing to issue certificate. Subject Common Name is on the "
                           "TINYPKI_DISALLOWED_NAMES list.")

    if any((san in TINYPKI_DISALLOWED_NAMES) for san in sans_vals):
        raise RuntimeError("Refusing to issue certificate. Some subject alternative names "
                           "are on the TINYPKI_DISALLOWED_NAMES list.")

    jwt_body = {
        "aud": TINYPKI_STEP_CA_URL + "/1.0/sign",
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=5),
        "iat": datetime.now(tz=timezone.utc),
        "nbf": datetime.now(tz=timezone.utc),
        "jti": str(uuid.uuid4()),
        "iss": provisioner["name"],
        "sans": sans_vals,
        "sub": cn if cn else sans_vals[0],
    }

    key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(provisioner["jwk"])
    ott = jwt.encode(
        jwt_body,
        key=key,
        headers={"kid": provisioner["jwk"]["kid"]},
        algorithm="ES256"
    )

    async with httpx.AsyncClient(verify=await get_step_ca_verify()) as client:
        res = await client.post(TINYPKI_STEP_CA_URL + '/1.0/sign',
                                json={
                                    'csr': csr_pem,
                                    'ott': ott,
                                    'notBefore': not_before,
                                    'notAfter': not_after,
                                    'templateData': template_data
                                })
        await res.aread()

        if res.status_code == 403 and res.headers['Content-Type'] == 'application/json':
            obj = res.json()
            raise StepSignError(obj['message'])
        else:
            res.raise_for_status()

        obj = res.json()

    chain = [x509.load_pem_x509_certificate(str.encode(pem)) for pem in obj['certChain']]
    cert = x509.load_pem_x509_certificate(str.encode(obj['crt']))
    return {
        "chain": chain,
        "cert": cert
    }
