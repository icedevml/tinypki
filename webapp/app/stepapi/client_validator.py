import traceback
from collections import OrderedDict

import httpx
from asn1crypto import pem, x509
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule

from .ca_fingerprint import get_step_ca_verify
from ..config import TINYPKI_STEP_CA_URL
from ..internal.exc import TinyPKIError, TinyPKIErrorReason


async def load_step_certs(path: str):
    async with httpx.AsyncClient(verify=await get_step_ca_verify()) as client:
        res = await client.get(TINYPKI_STEP_CA_URL + path)
        res.raise_for_status()

    for cert_pem in res.json()["crts"]:
        _, _, cert_bytes = pem.unarmor(cert_pem.encode("ascii"))
        yield x509.Certificate.load(cert_bytes)


def get_name_dict(subject: x509.Name):
    data = OrderedDict()
    last_field = None

    for rdn in subject.chosen:
        for type_val in rdn:
            field_name = type_val['type'].human_friendly
            last_field = field_name
            if field_name in data:
                data[field_name] = [data[field_name]]
                data[field_name].append(type_val['value'])
            else:
                data[field_name] = type_val['value']

    out = {}
    keys = data.keys()

    if last_field == 'Country':
        keys = reversed(list(keys))

    for key in keys:
        value = data[key]
        out[key] = subject._recursive_humanize(value)

    return out


async def validate_client_cert(client_cert: bytes, crl: bytes):
    cert = x509.Certificate.load(client_cert)

    revinfo_policy = CertRevTrustPolicy(
        revocation_checking_policy=RevocationCheckingPolicy(
            ee_certificate_rule=RevocationCheckingRule.CHECK_IF_DECLARED,
            intermediate_ca_cert_rule=RevocationCheckingRule.CHECK_IF_DECLARED,
        )
    )
    trust_roots = [cert async for cert in load_step_certs("/roots")]
    intermediates = [cert async for cert in load_step_certs("/intermediates")]
    context = ValidationContext(
        trust_roots=trust_roots,
        crls=[crl],
        allow_fetching=False,
        revinfo_policy=revinfo_policy
    )

    try:
        validator = CertificateValidator(cert, intermediates, context)
        await validator.async_validate_usage(key_usage={"digital_signature"}, extended_key_usage={"client_auth"})
    except (PathValidationError, RevokedError, InvalidCertificateError):
        traceback.print_exc()
        raise TinyPKIError(401, TinyPKIErrorReason.CLIENT_CERT_INVALID)

    return get_name_dict(cert.subject)
