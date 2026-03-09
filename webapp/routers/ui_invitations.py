import base64
import datetime
import os
from dataclasses import dataclass
from typing import Type

import psycopg2
from fastapi import APIRouter, Request, Depends
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError, NoResultFound
from sqlmodel import Session, select, or_, and_
from starlette.responses import HTMLResponse, RedirectResponse
from starlette_wtf import csrf_protect
from wtforms.validators import DataRequired, AnyOf

from ..dbmodels.tinypki import TinyInvitation, TinyBlueprint, SubjectMode, InvitationStatus
from ..dependencies import get_session, templates
from ..forms.invitations import SimpleDNSSANAddInvitationForm, BaseAddInvitationForm, DefaultAddInvitationForm, \
    SimpleEmailSANAddInvitationForm, DeleteInvitationForm
from ..internal.duration import parse_go_duration
from ..internal.exc import TinyPKIErrorReason, TinyPKIError
from ..internal.redeem_helpers import make_redeem_code, hash_redeem_code
from ..stepapi.provisioner import get_provisioner_record

router = APIRouter()


@dataclass
class InvitationAddDefaults:
    not_after_days: int
    invitation_validity_days: int


async def map_subject_mode_to_form(request: Request, blueprint: Type[TinyBlueprint]) -> BaseAddInvitationForm:
    obj = InvitationAddDefaults(
        not_after_days=blueprint.not_after_days,
        invitation_validity_days=blueprint.invitation_validity_days
    )

    if blueprint.subject_mode == SubjectMode.DEFAULT:
        return await DefaultAddInvitationForm.from_formdata(request, obj=obj)
    elif blueprint.subject_mode == SubjectMode.SIMPLE_DNS:
        return await SimpleDNSSANAddInvitationForm.from_formdata(request, obj=obj)
    elif blueprint.subject_mode == SubjectMode.SIMPLE_EMAIL:
        return await SimpleEmailSANAddInvitationForm.from_formdata(request, obj=obj)
    else:
        raise ValueError("Unsupported subject_mode: " + blueprint.subject_mode.name)


@router.get("/ui/invitations", response_class=HTMLResponse, include_in_schema=False)
def route_ui_list_invitations(
        request: Request,
        session: Session = Depends(get_session)
):
    invitations = session.exec(
        select(TinyInvitation)
        .order_by(TinyInvitation.id.desc())
    ).all()

    blueprints = session.exec(
        select(TinyBlueprint)
    ).all()

    now = datetime.datetime.now().replace(tzinfo=None)

    return templates.TemplateResponse(
        "invitations.html",
        {
            "request": request,
            "invitations": invitations,
            "blueprints": blueprints,
            "now": now
        }
    )


async def _process_invitation_add(request: Request, session: Session, blueprint: Type[TinyBlueprint],
                            form: BaseAddInvitationForm):
    redeem_code = make_redeem_code()
    redeem_code_hash = hash_redeem_code(redeem_code)

    cn = form.assemble_subject_cn()
    sans = form.assemble_sans()

    expires_at = datetime.datetime.now(datetime.timezone.utc) \
                 + datetime.timedelta(days=blueprint.invitation_validity_days)

    provisioner = await get_provisioner_record(blueprint.provisioner_name)

    if not provisioner:
        raise TinyPKIError(404, TinyPKIErrorReason.NO_SUCH_JWK_PROVISIONER)

    max_cert_duration_s = parse_go_duration(
        provisioner.get("claims", {}).get("maxTLSCertDuration", "24h"))

    if max_cert_duration_s < form.not_after_days.data * 24 * 60 * 60:
        raise TinyPKIError(400, TinyPKIErrorReason.UNACCEPTABLE_CERT_DURATION)

    obj = TinyInvitation(
        blueprint_name=blueprint.name,
        submit_nonce=form.submit_nonce.data,
        redeem_code_hash=redeem_code_hash,
        subject_common_name=cn,
        subject_alt_names=sans,
        not_after_days=form.not_after_days.data,
        expires_at=expires_at,
        status=InvitationStatus.CREATED,
        serial_no=None
    )

    try:
        session.add(obj)
        session.commit()
    except IntegrityError as e:
        if isinstance(e.orig, psycopg2.errors.UniqueViolation):
            raise TinyPKIError(400, TinyPKIErrorReason.INVITATION_ALREADY_CREATED)
        else:
            raise e

    return templates.TemplateResponse(
        "invitation_added.html",
        {
            "request": request,
            "subject_common_name": cn,
            "subject_alt_names": sans,
            "redeem_code": redeem_code,
        }
    )


@router.get("/ui/invitations/add/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/invitations/add/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_invitation_add(
        blueprint_name: str,
        request: Request,
        session: Session = Depends(get_session)
):
    submit_nonce = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").replace("=", "")
    blueprint = session.get_one(TinyBlueprint, blueprint_name)
    form = await map_subject_mode_to_form(request, blueprint)

    if await form.validate_on_submit():
        return await _process_invitation_add(request, session, blueprint, form)

    return templates.TemplateResponse(
        "invitation_add.html",
        {
            "request": request,
            "blueprint": blueprint,
            "form": form,
            "submit_nonce": submit_nonce,
        }
    )


@csrf_protect
@router.get("/ui/invitations/{invitation_id}/delete", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/invitations/{invitation_id}/delete", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_invitations_delete(
        invitation_id: int,
        request: Request,
        session: Session = Depends(get_session)
):
    try:
        invitation = session.get_one(TinyInvitation, invitation_id)
    except NoResultFound:
        raise TinyPKIError(404, TinyPKIErrorReason.OBJECT_NOT_FOUND)

    if invitation.status != InvitationStatus.CREATED and invitation.status != InvitationStatus.OPENED:
        raise TinyPKIError(400, TinyPKIErrorReason.UNABLE_TO_DELETE_RESOURCE_HAS_DEPENDENCIES)

    form = await DeleteInvitationForm.from_formdata(request)
    form.name.label.text = f"Type '{invitation.subject_common_name}' to confirm"
    form.name.validators = [DataRequired(), AnyOf([invitation.subject_common_name])]

    if await form.validate_on_submit():
        session.exec(
            delete(TinyInvitation)
            .where(
                and_(
                    TinyInvitation.id == invitation_id,
                    TinyInvitation.subject_common_name == form.name.data,
                    or_(
                        TinyInvitation.status == InvitationStatus.CREATED,
                        TinyInvitation.status == InvitationStatus.OPENED
                    )
                )
            ))
        session.commit()

        return RedirectResponse("/ui/invitations", status_code=302)

    return templates.TemplateResponse(
        "invitation_delete.html",
        {
            "request": request,
            "form": form,
            "invitation": invitation,
        }
    )
