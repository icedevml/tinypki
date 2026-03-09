import time

import psycopg2
from fastapi import APIRouter, Request, Depends
from jwcrypto import jwt
from jwcrypto.jwe import InvalidJWEData
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from starlette.responses import HTMLResponse, RedirectResponse
from starlette_wtf import csrf_protect
from wtforms.validators import DataRequired, AnyOf

from ..dbmodels.tinypki import TinyJWKProvisioner
from ..dependencies import get_session, templates
from ..forms.provisioners import AddProvisionerForm, DeleteProvisionerForm
from ..internal.atrest_key import create_atrest_jwk
from ..internal.exc import ProvisionerNotFound, TinyPKIError, TinyPKIErrorReason
from ..stepapi.provisioner import get_provisioner_jwk

router = APIRouter()


@csrf_protect
@router.get("/ui/provisioners", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/provisioners", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_list_provisioners(
        request: Request,
        session: Session = Depends(get_session)
):
    provisioners = session.exec(
        select(TinyJWKProvisioner)
    ).all()

    return templates.TemplateResponse(
        "provisioners.html",
        {
            "request": request,
            "provisioners": provisioners,
        }
    )


async def _process_provisioner_add(session: Session, form: AddProvisionerForm):
    try:
        provisioner = await get_provisioner_jwk(form.name.data, password=form.password.data)
    except (ProvisionerNotFound, InvalidJWEData):
        raise TinyPKIError(403, TinyPKIErrorReason.PROVISIONER_FAILED_LOGIN)

    key = create_atrest_jwk()

    plaintext_to_enc = {
        "provisioner": provisioner,
        "iat": int(time.time()),
        "aud": "stored-jwk-provisioner"
    }
    protected_hdr = {
        "alg": "A256GCMKW",
        "enc": "A256GCM",
        "kid": key["kid"],
    }

    token_obj = jwt.JWT(header=protected_hdr, claims=plaintext_to_enc)
    token_obj.make_encrypted_token(key=key)
    token = token_obj.serialize()

    # check if there is any provisioner in the DB already
    is_default = form.make_default.data
    count = session.exec(select(func.count()).select_from(TinyJWKProvisioner)).one()

    if count == 0:
        is_default = True

    try:
        session.add(TinyJWKProvisioner(
            name=form.name.data,
            provisioner_jwe=token,
            provisioner_jwe_kid=key["kid"],
            is_default=is_default,
        ))
        session.commit()
    except IntegrityError:
        raise TinyPKIError(403, TinyPKIErrorReason.PROVISIONER_ALREADY_EXISTS)

    return RedirectResponse("/ui/provisioners", status_code=302)


@csrf_protect
@router.get("/ui/provisioners/add", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/provisioners/add", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_provisioner_add(
        request: Request,
        session: Session = Depends(get_session)
):
    count = session.exec(select(func.count()).select_from(TinyJWKProvisioner)).one()
    form = await AddProvisionerForm.from_formdata(request)

    if count == 0:
        form.make_default.render_kw = {"disabled": True, "checked": True}

    if await form.validate_on_submit():
        return await _process_provisioner_add(session, form)

    return templates.TemplateResponse(
        "provisioner_add.html",
        {
            "request": request,
            "form": form
        }
    )


@csrf_protect
@router.get("/ui/provisioners/{name}/delete", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/provisioners/{name}/delete", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_provisioner_delete(
        name: str,
        request: Request,
        session: Session = Depends(get_session)
):
    provisioner = session.get_one(TinyJWKProvisioner, name)

    form = await DeleteProvisionerForm.from_formdata(request)
    form.name.label.text = f"Type '{provisioner.name}' to confirm"
    form.name.validators = [DataRequired(), AnyOf([provisioner.name])]

    if await form.validate_on_submit():
        try:
            session.delete(provisioner)
            session.commit()
        except IntegrityError as e:
            if isinstance(e.orig, psycopg2.errors.IntegrityError):
                raise TinyPKIError(400, TinyPKIErrorReason.UNABLE_TO_DELETE_RESOURCE_HAS_DEPENDENCIES)
            else:
                raise e

        return RedirectResponse("/ui/provisioners", status_code=302)

    return templates.TemplateResponse(
        "provisioner_delete.html",
        {
            "request": request,
            "form": form,
            "provisioner": provisioner,
        }
    )
