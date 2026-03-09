import json
import traceback
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding
from fastapi import APIRouter, Depends
from jwcrypto import jwt
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlmodel import Session

from ..dbmodels.tinypki import TinyInvitation, KeygenFlow, InvitationStatus
from ..dependencies import get_session
from ..internal.atrest_key import create_atrest_jwk
from ..internal.duration import days_to_go_duration
from ..internal.exc import TinyPKIError, TinyPKIErrorReason
from ..internal.key_spec import KeySpec
from ..internal.redeem_helpers import make_pkcs12_password
from ..internal.redeem_logic import lock_invitation, decrypt_invitation_jwk_provisioner, \
    create_api_redeem_token, find_invitation, do_redeem_code
from ..stepapi.sign import sign_cert, CSR

router = APIRouter()


class RedeemInitRequestData(BaseModel):
    redeem_code: str = Field(
        examples=["WXFB-ADTM-E8LE-F3EE-Z73R"],
        description="Invitation code as received from the system operator."
    )


class RedeemInitRequirements(BaseModel):
    keygen_flow: str = Field(examples=["CLIENT_SIDE", "SERVER_SIDE"])
    key_algorithm: str = Field(examples=["ECDSA/P-256/SHA-256"])
    key_spec: dict = Field(examples=[{
      "algorithm": "ECDSA",
      "curve": "P-256",
      "hash_algorithm": "SHA-256"
    }])
    cn: str = Field(examples=["janusz@example.com"])
    sans: list[str] = Field(examples=[["email:janusz@example.com"]])


class RedeemInitResponseData(BaseModel):
    requirements: RedeemInitRequirements = Field()
    pkcs12_password: Optional[str] = Field(
        default=None,
        examples=[None, "wy3xcz97pdvp"]
    )
    token: str = Field(
        examples=["eyJhbGciOiJBMjU2R0NNS1ciLCJlb..."]
    )


class RedeemWithCSRRequestData(BaseModel):
    token: str = Field(
        examples=["eyJhbGciOiJBMjU2R0NNS1ciLCJlb..."],
        description="Token received from the /public/api/redeem/init endpoint."
    )
    csr: str = Field(
        examples=["-----BEGIN CERTIFICATE REQUEST-----\nMIIBGTCBwAIBADAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABJba9F4FeJJE78mwwy3BfKCFZ4t7vaHgwnBP855qrsLL9Dh1\nAaMb/6WjGeDCKyEHY3cE205xIwF4LqB8VTFcl1OgSDBGBgkqhkiG9w0BCQ4xOTA3\nMAsGA1UdDwQEAwIFoDAoBgNVHREEITAfgRB0ZXN0QGV4YW1wbGUuY29tggtleGFt\ncGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiBbRgdMbyrSP3a2x2rvLgZR6W8Vg8k5\nakcLh+bM6QESwAIhANZd7ROg81pkaUQWjeRgsmLHpo53PHe+flDIp+ir5D1t\n-----END CERTIFICATE REQUEST-----"],
        description="PKCS#10 Certificate Signing Request (CSR) conformant with the requirements specified by the server."
    )


class RedeemServerSideRequestData(BaseModel):
    token: str = Field(
        examples=["eyJhbGciOiJBMjU2R0NNS1ciLCJlb..."],
        description="Token received from the /public/api/redeem/init endpoint."
    )


@router.post(
    "/public/api/redeem/init",
    response_model=RedeemInitResponseData,
    summary="Begin the certificate retrieval process using an invitation code.",
    responses={
        200: {"description": "Certificate retrieval process details"}
    }
)
async def route_public_api_redeem_init(
        data: RedeemInitRequestData,
        session: Session = Depends(get_session)
):
    invitation = find_invitation(session, data.redeem_code)

    out = {
        "requirements": {
            "keygen_flow": invitation.blueprint.keygen_flow.name,
            "key_algorithm": invitation.blueprint.key_algorithm,
            "key_spec": KeySpec.from_string(invitation.blueprint.key_algorithm).to_dict(),
            "cn": invitation.subject_common_name,
            "sans": invitation.subject_alt_names,
        }
    }

    if invitation.blueprint.keygen_flow == KeygenFlow.SERVER_SIDE:
        pkcs12_password = make_pkcs12_password(length=12)
        token = create_api_redeem_token(invitation, "invite-redeem-server-side", pkcs12_password)

        out.update({
            "pkcs12_password": pkcs12_password,
            "token": token
        })
        return RedeemInitResponseData(**out)
    elif invitation.blueprint.keygen_flow == KeygenFlow.CLIENT_SIDE:
        token = create_api_redeem_token(invitation, "invite-redeem-client-side")

        out.update({
            "token": token
        })
        return RedeemInitResponseData(**out)
    else:
        raise ValueError("Unsupported KeygenFlow type: " + invitation.blueprint.keygen_flow.name)


class RedeemClientSideResponseData(BaseModel):
    certChain: str = Field(description="Certificate chain (PEM-formatted string)")


@router.post(
    "/public/api/redeem/client-side",
    response_model=RedeemClientSideResponseData,
    summary="Submit a locally-generated PKCS#10 Certificate Signing Request (CSR) to redeem the certificate.",
    responses={
        200: {"description": "The issued X.509 certificate together with the intermediate certificate chain."}
    }
)
async def route_public_api_redeem_client_side(
        data: RedeemWithCSRRequestData,
        session: Session = Depends(get_session)
):
    key = create_atrest_jwk()

    token = jwt.JWT(algs=["A256GCMKW", "A256GCM"], check_claims={"aud": "invite-redeem-client-side"})
    token.deserialize(data.token, key=key)
    claims = json.loads(token.claims)

    their_redeem_code_hash = claims["redeem_code_hash"]

    invitation = lock_invitation(session, redeem_code_hash=their_redeem_code_hash)

    try:
        provisioner = decrypt_invitation_jwk_provisioner(invitation)

        if invitation.blueprint.keygen_flow != KeygenFlow.CLIENT_SIDE:
            raise RuntimeError("Trying to perform client-side key generation for invitation that requested "
                               "server-side key generation.")

        csr = CSR.from_pem(
            data.csr,
            required_cn=invitation.subject_common_name,
            required_sans=invitation.subject_alt_names,
            required_key_algorithm=invitation.blueprint.key_algorithm
        )
        sign_res = await sign_cert(
            provisioner=provisioner,
            csr_pem=csr.csr_pem_bytes.decode("ascii"),
            cn=invitation.subject_common_name,
            sans=invitation.subject_alt_names,
            not_before=invitation.blueprint.not_before,
            not_after=days_to_go_duration(invitation.not_after_days),
            template_data=dict()
        )
        cert: x509.Certificate = sign_res["cert"]
        cert_chain: List[x509.Certificate] = sign_res["chain"]

        if cert.serial_number != cert_chain[0].serial_number:
            raise RuntimeError("Sanity check failed: the certificate chain returned by the CA does not contain "
                               "the leaf certificate on the first position.")
    except Exception:  # noqa
        tb = traceback.format_exc()
        traceback.print_exc()

        session.exec(
            update(TinyInvitation)
            .where(TinyInvitation.redeem_code_hash == invitation.redeem_code_hash)
            .values(status=InvitationStatus.EXCEPTION, error_message=tb)
        )
        session.commit()

        raise TinyPKIError(status_code=500, reason=TinyPKIErrorReason.CERT_ISSUANCE_ERROR)

    session.exec(
        update(TinyInvitation)
        .where(TinyInvitation.redeem_code_hash == invitation.redeem_code_hash)
        .values(status=InvitationStatus.ISSUED, serial_no=str(cert.serial_number), keygen_flow=KeygenFlow.CLIENT_SIDE)
    )
    session.commit()

    return {
        "certChain": "\n".join(cert.public_bytes(Encoding.PEM).strip().decode("ascii") for cert in cert_chain)
    }


class RedeemServerSideResponseData(BaseModel):
    pkcs12B64: str = Field(
        description="The issued PKCS#12, base64-encoded.",
        examples=["MIIJAQIBAzCCCMcGCSqGSIb3DQEHAa..."]
    )


@router.post(
    "/public/api/redeem/server-side",
    response_model=RedeemServerSideResponseData,
    summary="Request a private key and certificate generation on the server, and retrieve the PKCS#12 container.",
    responses={
        200: {"description": "The issued PKCS#12 container with the private key and issued certificate."}
    }
)
async def route_public_api_redeem_server_side(
        data: RedeemServerSideRequestData,
        session: Session = Depends(get_session),
):
    key = create_atrest_jwk()

    token = jwt.JWT(algs=["A256GCMKW", "A256GCM"], check_claims={"aud": "invite-redeem-server-side"})
    token.deserialize(data.token, key=key)
    claims = json.loads(token.claims)

    their_redeem_code_hash = claims["redeem_code_hash"]
    pkcs12_password = claims["pkcs12_password"]

    res = await do_redeem_code(
        session=session,
        their_redeem_code_hash=their_redeem_code_hash,
        pkcs12_password=pkcs12_password)

    return {
        "pkcs12B64": res["private"]["pkcs12_b64"],
    }
