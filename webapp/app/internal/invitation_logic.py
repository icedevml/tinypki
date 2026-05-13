import datetime

import psycopg2
from sqlalchemy.exc import IntegrityError, NoResultFound
from sqlmodel import Session, delete, and_, or_

from ..dbmodels.tinypki import TinyInvitation, TinyBlueprint, InvitationStatus
from ..internal.duration import parse_go_duration
from ..internal.exc import TinyPKIError, TinyPKIErrorReason
from ..internal.redeem_helpers import make_redeem_code, hash_redeem_code
from ..internal.util import make_submit_nonce
from ..stepapi.provisioner import get_provisioner_record


async def create_invitation(
        session: Session,
        blueprint: TinyBlueprint,
        not_after_days: int,
        cn: str,
        sans: list[str],
) -> tuple[TinyInvitation, str]:
    """
    Returns (invitation_obj, plaintext_redeem_code).
    """
    redeem_code = make_redeem_code()
    redeem_code_hash = hash_redeem_code(redeem_code)

    expires_at = datetime.datetime.now(datetime.timezone.utc) \
                 + datetime.timedelta(days=blueprint.invitation_validity_days)

    provisioner = await get_provisioner_record(blueprint.provisioner_name)
    if not provisioner:
        raise TinyPKIError(404, TinyPKIErrorReason.NO_SUCH_JWK_PROVISIONER)

    max_cert_duration_s = parse_go_duration(
        provisioner.get("claims", {}).get("maxTLSCertDuration", "24h"))
    if max_cert_duration_s < not_after_days * 24 * 60 * 60:
        raise TinyPKIError(400, TinyPKIErrorReason.UNACCEPTABLE_CERT_DURATION)

    obj = TinyInvitation(
        blueprint_name=blueprint.name,
        submit_nonce=make_submit_nonce(),  # generated internally — no form needed
        redeem_code_hash=redeem_code_hash,
        subject_common_name=cn,
        subject_alt_names=sans,
        not_after_days=not_after_days,
        expires_at=expires_at,
        status=InvitationStatus.CREATED,
        serial_no=None,
    )

    try:
        session.add(obj)
        session.commit()
        session.refresh(obj)
    except IntegrityError as e:
        if isinstance(e.orig, psycopg2.errors.UniqueViolation):
            raise TinyPKIError(400, TinyPKIErrorReason.INVITATION_ALREADY_CREATED)
        raise

    return obj, redeem_code


async def get_deletable_invitation(
        session: Session,
        invitation_id: int
) -> TinyInvitation:
    try:
        invitation = session.get_one(TinyInvitation, invitation_id)
    except NoResultFound:
        raise TinyPKIError(404, TinyPKIErrorReason.OBJECT_NOT_FOUND)

    if invitation.status not in (InvitationStatus.CREATED, InvitationStatus.OPENED):
        raise TinyPKIError(400, TinyPKIErrorReason.UNABLE_TO_DELETE_RESOURCE_HAS_DEPENDENCIES)

    return invitation


async def delete_invitation(
        session: Session,
        invitation_id: int,
) -> None:
    await get_deletable_invitation(session, invitation_id)

    session.exec(
        delete(TinyInvitation)
        .where(
            and_(
                TinyInvitation.id == invitation_id,
                or_(
                    TinyInvitation.status == InvitationStatus.CREATED,
                    TinyInvitation.status == InvitationStatus.OPENED,
                )
            )
        )
    )
    session.commit()
