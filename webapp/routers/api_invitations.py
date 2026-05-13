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


class InvitationCreateRequest(BaseModel):
    not_after_days: int
    subject_name: str | None = None          # for SIMPLE_DNS / SIMPLE_EMAIL modes
    subject_common_name: str | None = None   # for DEFAULT mode
    subject_alt_names: list[str] | None = None  # for DEFAULT mode, e.g. ["dns:example.com"]


class InvitationCreateResponse(BaseModel):
    id: int
    subject_common_name: str
    subject_alt_names: list[str]
    redeem_code: str
    expires_at: str


class InvitationOut(BaseModel):
    id: int = Field(...)

    blueprint_name: str = Field(...)

    subject_common_name: str = Field(...)
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

    match blueprint.subject_mode:
        case SubjectMode.SIMPLE_DNS:
            if not body.subject_name:
                raise HTTPException(422, "subject_name required for SIMPLE_DNS blueprints")
            cn = body.subject_name
            sans = [f"dns:{body.subject_name}"]

        case SubjectMode.SIMPLE_EMAIL:
            if not body.subject_name:
                raise HTTPException(422, "subject_name required for SIMPLE_EMAIL blueprints")
            cn = body.subject_name
            sans = [f"email:{body.subject_name}"]

        case SubjectMode.DEFAULT:
            if not body.subject_common_name or not body.subject_alt_names:
                raise HTTPException(422, "subject_common_name and subject_alt_names required for DEFAULT blueprints")
            cn = body.subject_common_name
            sans = body.subject_alt_names

        case _:
            raise HTTPException(500, "Unsupported subject_mode")

    try:
        invitation, redeem_code = await create_invitation(
            session, blueprint, body.not_after_days, cn, sans
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
