import datetime
from dataclasses import dataclass
from typing import Type

from fastapi import APIRouter, Request, Depends
from sqlmodel import Session, select
from starlette.responses import HTMLResponse, RedirectResponse
from starlette_wtf import csrf_protect
from wtforms.validators import DataRequired, AnyOf

from ..dbmodels.tinypki import TinyInvitation, TinyBlueprint, SubjectMode
from ..dependencies import get_session, templates
from ..forms.invitations import SimpleDNSSANAddInvitationForm, BaseAddInvitationForm, DefaultAddInvitationForm, \
    SimpleEmailSANAddInvitationForm, DeleteInvitationForm
from ..internal.invitation_logic import create_invitation, delete_invitation, get_deletable_invitation
from ..internal.util import make_submit_nonce

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


async def _process_invitation_add(request, session, blueprint, form):
    cn = form.assemble_subject_cn()
    sans = form.assemble_sans()

    invitation, redeem_code = await create_invitation(
        session, blueprint, form.not_after_days.data, cn, sans
    )

    return templates.TemplateResponse(
        "invitation_added.html",
        {
            "request": request,
            "subject_common_name": cn,
            "subject_alt_names": sans,
            "redeem_code": redeem_code
        }
    )


@router.get("/ui/invitations/add/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/invitations/add/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_invitation_add(
        blueprint_name: str,
        request: Request,
        session: Session = Depends(get_session)
):
    submit_nonce = make_submit_nonce()
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
    invitation = await get_deletable_invitation(session, invitation_id)

    form = await DeleteInvitationForm.from_formdata(request)
    form.name.label.text = f"Type '{invitation.subject_common_name}' to confirm"
    form.name.validators = [DataRequired(), AnyOf([invitation.subject_common_name])]

    if await form.validate_on_submit():
        await delete_invitation(session, invitation_id)
        return RedirectResponse("/ui/invitations", status_code=302)

    return templates.TemplateResponse(
        "invitation_delete.html",
        {
            "request": request,
            "form": form,
            "invitation": invitation,
        }
    )
