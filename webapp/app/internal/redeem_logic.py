import datetime
import json
import time
import traceback
from typing import Optional

from cryptography import x509
from fastapi import HTTPException
from jwcrypto import jwt
from jwcrypto.common import JWException
from sqlalchemy import update
from sqlalchemy.exc import NoResultFound
from sqlmodel import Session, select, and_, or_

from .duration import days_to_go_duration
from .exc import TinyPKIError, TinyPKIErrorReason
from .key_spec import KeySpec
from .redeem_helpers import hash_redeem_code
from ..dbmodels.tinypki import TinyInvitation, KeygenFlow, InvitationStatus
from ..internal.atrest_key import create_atrest_jwk
from ..internal.issue_pkcs12 import issue_pkcs12
from ..middleware import app_logger
from ..stepapi.sign import sign_cert, CSR


def lock_invitation(session: Session, *, redeem_code_hash: str) -> TinyInvitation:
    # perform optimistic update and check if we've succeeded
    # if not, then it will mean a race condition
    result = session.exec(
        update(TinyInvitation)
        .where(and_(
            TinyInvitation.redeem_code_hash == redeem_code_hash,
            TinyInvitation.expires_at > datetime.datetime.now(),
            TinyInvitation.status == InvitationStatus.OPENED
        ))
        .values(status=InvitationStatus.LOCKED)
    )
    session.commit()

    if result.rowcount != 1:
        raise TinyPKIError(status_code=403, reason=TinyPKIErrorReason.REDEEM_CODE_EXPIRED)

    return session.exec(
        select(TinyInvitation)
        .where(TinyInvitation.redeem_code_hash == redeem_code_hash)
    ).one()


def decrypt_invitation_jwk_provisioner(invitation: TinyInvitation):
    if not invitation.blueprint.jwk_provisioner:
        raise TinyPKIError(status_code=500, reason=TinyPKIErrorReason.NO_SUCH_JWK_PROVISIONER)

    token = jwt.JWT(algs=["A256GCMKW", "A256GCM"], check_claims={"aud": "stored-jwk-provisioner"})

    try:
        token.deserialize(invitation.blueprint.jwk_provisioner.provisioner_jwe, key=create_atrest_jwk())
    except JWException:
        app_logger.exception("Failed to decode JWT.")
        raise HTTPException(401, "Invalid token.")

    return json.loads(token.claims)["provisioner"]


async def do_redeem_code(
        *,
        session: Session,
        their_redeem_code_hash: str,
        pkcs12_password: str
):
    invitation = lock_invitation(session, redeem_code_hash=their_redeem_code_hash)

    if invitation.blueprint.keygen_flow != KeygenFlow.SERVER_SIDE:
        raise RuntimeError("Trying to perform server-side key generation for invitation that doesn't request it.")

    provisioner = decrypt_invitation_jwk_provisioner(invitation)

    try:
        csr = CSR(cn=invitation.subject_common_name, sans=invitation.subject_alt_names)
        csr.generate(KeySpec.from_string(invitation.blueprint.key_algorithm))

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

        session.exec(
            update(TinyInvitation)
            .where(TinyInvitation.redeem_code_hash == invitation.redeem_code_hash)
            .values(status=InvitationStatus.ISSUED, serial_no=str(cert.serial_number),
                    keygen_flow=KeygenFlow.SERVER_SIDE)
        )
        session.commit()

        res = issue_pkcs12(sign_res, csr.private_key, pkcs12_password)
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

    return res


def find_invitation(session: Session, redeem_code: str):
    their_redeem_code_hash = hash_redeem_code(redeem_code)

    try:
        out = session.exec(
            select(TinyInvitation)
            .where(and_(
                TinyInvitation.redeem_code_hash == their_redeem_code_hash,
                TinyInvitation.expires_at > datetime.datetime.now(datetime.timezone.utc),
                or_(
                    TinyInvitation.status == InvitationStatus.CREATED,
                    TinyInvitation.status == InvitationStatus.OPENED
                )
            ))
        ).one()
    except NoResultFound:
        raise TinyPKIError(403, TinyPKIErrorReason.REDEEM_CODE_EXPIRED)

    # update status to "OPENED" only if the current status is "CREATED"
    session.exec(
        update(TinyInvitation)
        .where(and_(
            TinyInvitation.redeem_code_hash == out.redeem_code_hash,
            TinyInvitation.status == InvitationStatus.CREATED
        ))
        .values(status=InvitationStatus.OPENED)
    )
    session.commit()
    return out


def create_api_redeem_token(invitation: TinyInvitation, flow: str, pkcs12_password: Optional[str] = None):
    key = create_atrest_jwk()

    if flow not in ["invite-redeem-server-side", "invite-redeem-client-side"]:
        raise ValueError("Invalid flow.")

    plaintext_to_enc = {
        "redeem_code_hash": invitation.redeem_code_hash,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 60 * 15,
        "aud": flow
    }

    if flow == "invite-redeem-server-side":
        plaintext_to_enc.update({"pkcs12_password": pkcs12_password})

    protected_hdr = {
        "alg": "A256GCMKW",
        "enc": "A256GCM",
        "kid": key["kid"],
    }

    token_obj = jwt.JWT(header=protected_hdr, claims=plaintext_to_enc)
    token_obj.make_encrypted_token(key=key)
    return token_obj.serialize()
