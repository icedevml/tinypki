from fastapi import APIRouter, Request, Depends
from sqlmodel import Session
from starlette.responses import HTMLResponse
from starlette_wtf import csrf_protect

from ..dbmodels.tinypki import KeygenFlow
from ..dependencies import get_session, templates
from ..forms.redeem import RedeemInvitationForm, RedeemStep2Form
from ..internal.redeem_helpers import make_pkcs12_password
from ..internal.redeem_logic import create_api_redeem_token, find_invitation

router = APIRouter()


@csrf_protect
@router.get("/public/ui/redeem", response_class=HTMLResponse, include_in_schema=False)
@router.post("/public/ui/redeem", response_class=HTMLResponse, include_in_schema=False)
async def route_public_ui_redeem(
        request: Request,
        session: Session = Depends(get_session)
):
    form = await RedeemInvitationForm.from_formdata(request)

    if await form.validate_on_submit():
        invitation = find_invitation(session, redeem_code=form.redeem_code.data)
        pkcs12_password = make_pkcs12_password(length=16)

        if invitation.blueprint.keygen_flow == KeygenFlow.SERVER_SIDE:
            token_sgen = create_api_redeem_token(invitation, "invite-redeem-server-side", pkcs12_password)
            frontend_cfg = {
                "flowType": "SERVER_SIDE",
                "serverSideFlowConfig": {
                    "token": token_sgen,
                    "pkcs12_password": pkcs12_password,
                }
            }
        elif invitation.blueprint.keygen_flow == KeygenFlow.CLIENT_SIDE:
            token_csgen = create_api_redeem_token(invitation, "invite-redeem-client-side")
            frontend_cfg = {
                "flowType": "CLIENT_SIDE",
                "clientSideFlowConfig": {
                    "token": token_csgen,
                    "cn": invitation.subject_common_name,
                    "sans": invitation.subject_alt_names,
                    "keyAlgorithm": invitation.blueprint.key_algorithm,
                }
            }
        else:
            raise RuntimeError("Unsupported keygen flow: " + invitation.blueprint.keygen_flow.name)

        step2_form = RedeemStep2Form(request)
        return templates.TemplateResponse(
            "redeem_invitation_step2.html",
            {
                "request": request,
                "invitation": invitation,
                "step2_form": step2_form,
                "frontend_cfg": frontend_cfg,
            }
        )

    return templates.TemplateResponse(
        "redeem_invitation.html",
        {
            "request": request,
            "form": form
        }
    )
