from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select, or_

from ..dbmodels.tinypki import KeygenFlow, InvitationStatus, TinyInvitation, TinyBlueprint, SubjectMode
from ..dependencies import get_session
from ..internal.invitation_logic import create_invitation, delete_invitation
from ..internal.exc import TinyPKIError

router = APIRouter()


class ReqSimpleDNS(BaseModel):
    name: str


class ReqSimpleEmail(BaseModel):
    name: str


class ReqDefault(BaseModel):
    subject_common_name: str
    subject_alt_names: list[str]


class InvitationCreateRequest(BaseModel):
    subject_mode: SubjectMode
    req_simple_dns: ReqSimpleDNS | None = None
    req_simple_email: ReqSimpleEmail | None = None
    req_default: ReqDefault | None = None

    not_after_days: Optional[int] = Field(
        default=None, description="How many days the certificate will be valid after it's issued. "
                                  "Will use blueprint's default value if null is provided here.")


class InvitationCreateResponse(BaseModel):
    id: int
    subject_common_name: Optional[str]
    subject_alt_names: list[str]
    redeem_code: str
    expires_at: str


class InvitationOut(BaseModel):
    id: int = Field(...)

    blueprint_name: str = Field(...)

    subject_common_name: Optional[str] = Field(...)
    subject_alt_names: List[str] = Field(...)
    not_after_days: int = Field(...)

    status: InvitationStatus = Field(...)
    created_at: datetime = Field(...)
    expires_at: datetime = Field(...)

    serial_no: Optional[str] = Field(...)
    keygen_flow: Optional[KeygenFlow] = Field(...)
    error_message: Optional[str] = Field(...)

    model_config = {"from_attributes": True}


class ListInvitationsResponse(BaseModel):
    invitations: list[InvitationOut]


@router.get("/api/invitations")
def route_api_list_invitations(
        before_id: Optional[int] = Query(default=None),
        subject: Optional[str] = Query(default=None),
        session: Session = Depends(get_session)
) -> ListInvitationsResponse:
    query = select(TinyInvitation) \
        .order_by(TinyInvitation.id.desc())

    if before_id is not None:
        query = query.where(TinyInvitation.id < before_id)

    if subject is not None:
        query = query.where(or_(
            TinyInvitation.subject_common_name == subject,
            TinyInvitation.subject_alt_names.any(subject),
        ))

    invitations = list(session.exec(query.limit(100)).all())
    return ListInvitationsResponse(invitations=invitations)


@router.post("/api/invitations/{blueprint_name}")
async def api_create_invitation(
    blueprint_name: str,
    body: InvitationCreateRequest,
    session: Session = Depends(get_session),
) -> InvitationCreateResponse:
    try:
        blueprint = session.get_one(TinyBlueprint, blueprint_name)
    except Exception:
        raise HTTPException(status_code=404, detail="Blueprint not found")

    if body.subject_mode != blueprint.subject_mode:
        raise HTTPException(400, f"Blueprint '{blueprint_name}' requires subject_mode {blueprint.subject_mode.value}")

    not_after_days = body.not_after_days

    if not_after_days is None:
        not_after_days = blueprint.not_after_days

    match body.subject_mode:
        case SubjectMode.SIMPLE_DNS:
            if not body.req_simple_dns:
                raise HTTPException(422, "req_simple_dns is required for SIMPLE_DNS subject_mode")
            cn = body.req_simple_dns.name
            sans = [f"dns:{body.req_simple_dns.name}"]

        case SubjectMode.SIMPLE_EMAIL:
            if not body.req_simple_email:
                raise HTTPException(422, "req_simple_email is required for SIMPLE_EMAIL subject_mode")
            cn = None
            sans = [f"email:{body.req_simple_email.name}"]

        case SubjectMode.DEFAULT:
            if not body.req_default:
                raise HTTPException(422, "req_default is required for DEFAULT subject_mode")
            cn = None
            sans = body.req_default.subject_alt_names

        case _:
            raise HTTPException(500, "Unsupported subject_mode")

    try:
        invitation, redeem_code = await create_invitation(
            session, blueprint, not_after_days, cn, sans
        )
    except TinyPKIError as e:
        raise HTTPException(status_code=e.status_code, detail=e.reason.value)

    return InvitationCreateResponse(
        id=invitation.id,
        subject_common_name=invitation.subject_common_name,
        subject_alt_names=invitation.subject_alt_names,
        redeem_code=redeem_code,
        expires_at=invitation.expires_at.isoformat(),
    )


@router.delete("/api/invitations/{invitation_id}", status_code=204)
async def api_delete_invitation(
    invitation_id: int,
    session: Session = Depends(get_session),
):
    try:
        await delete_invitation(session, invitation_id)
    except TinyPKIError as e:
        raise HTTPException(status_code=e.status_code, detail=e.reason.value)
