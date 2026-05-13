from typing import Type

import psycopg2
from fastapi import APIRouter, Request, Depends
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from starlette.responses import HTMLResponse, RedirectResponse
from starlette_wtf import csrf_protect
from wtforms.validators import DataRequired, AnyOf

from ..dbmodels.tinypki import TinyJWKProvisioner, TinyBlueprint
from ..dependencies import get_session, templates
from ..forms.blueprints import AddBlueprintForm, EditBlueprintForm, DeleteBlueprintForm
from ..forms.provisioners import DeleteProvisionerForm
from ..internal.exc import TinyPKIError, TinyPKIErrorReason
from ..internal.key_spec import SUPPORTED_KEY_SPECS_STR

router = APIRouter()


@csrf_protect
@router.get("/ui/blueprints", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/blueprints", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_list_blueprints(
        request: Request,
        session: Session = Depends(get_session)
):
    delete_form = await DeleteProvisionerForm.from_formdata(request)

    if await delete_form.validate_on_submit():
        return RedirectResponse("/ui/blueprints", status_code=302)

    blueprints = session.exec(
        select(TinyBlueprint)
    ).all()

    return templates.TemplateResponse(
        "blueprints.html",
        {
            "request": request,
            "blueprints": blueprints,
            "delete_form": delete_form,
        }
    )


def _process_blueprint_add(session: Session, form: AddBlueprintForm):
    try:
        session.add(TinyBlueprint(
            name=form.name.data,
            provisioner_name=form.provisioner_name.data,
            invitation_validity_days=form.invitation_validity_days.data,
            not_before=form.not_before.data,
            not_after_days=form.not_after_days.data,
            key_algorithm=form.key_algorithm.data,
            keygen_flow=form.keygen_flow.data,
            subject_mode=form.subject_mode.data,
        ))
        session.commit()
    except IntegrityError:
        raise TinyPKIError(403, TinyPKIErrorReason.PROVISIONER_ALREADY_EXISTS)

    return RedirectResponse("/ui/blueprints", status_code=302)


@csrf_protect
@router.get("/ui/blueprints/add", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/blueprints/add", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_blueprint_add(
        request: Request,
        session: Session = Depends(get_session)
):
    provisioners = session.exec(
        select(TinyJWKProvisioner)
    ).all()

    if len(provisioners) == 0:
        raise TinyPKIError(400, TinyPKIErrorReason.NO_DEFAULT_PROVISIONER)

    form = await AddBlueprintForm.from_formdata(request)
    form.provisioner_name.choices = [(o.name, o.name) for o in provisioners]
    form.key_algorithm.choices = [(v, v) for v in SUPPORTED_KEY_SPECS_STR]

    if await form.validate_on_submit():
        return _process_blueprint_add(session, form)

    return templates.TemplateResponse(
        "blueprint_add.html",
        {
            "request": request,
            "form": form
        }
    )


def _process_blueprint_edit(session: Session, blueprint: Type[TinyBlueprint], form: EditBlueprintForm):
    blueprint.provisioner_name = form.provisioner_name.data
    blueprint.invitation_validity_days = form.invitation_validity_days.data
    blueprint.not_before = form.not_before.data
    blueprint.not_after_days = form.not_after_days.data
    blueprint.key_algorithm = form.key_algorithm.data
    blueprint.keygen_flow = form.keygen_flow.data
    blueprint.subject_mode = form.subject_mode.data

    session.merge(blueprint)
    session.commit()

    return RedirectResponse("/ui/blueprints", status_code=302)


@csrf_protect
@router.get("/ui/blueprints/edit/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/blueprints/edit/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_blueprint_edit(
        blueprint_name: str,
        request: Request,
        session: Session = Depends(get_session)
):
    blueprint = session.get_one(TinyBlueprint, blueprint_name)

    provisioners = session.exec(
        select(TinyJWKProvisioner)
    ).all()

    if len(provisioners) == 0:
        raise TinyPKIError(400, TinyPKIErrorReason.NO_DEFAULT_PROVISIONER)

    form = await EditBlueprintForm.from_formdata(request, obj=blueprint)
    delete_form = await DeleteBlueprintForm.from_formdata(request)
    delete_form.name.label = f"Type '{blueprint.name}' to confirm"
    delete_form.name.validators.append(AnyOf([blueprint.name]))

    form.provisioner_name.choices = [(o.name, o.name) for o in provisioners]
    form.key_algorithm.choices = [(v, v) for v in SUPPORTED_KEY_SPECS_STR]

    if await form.validate_on_submit():
        return _process_blueprint_edit(session, blueprint, form)

    return templates.TemplateResponse(
        "blueprint_edit.html",
        {
            "request": request,
            "form": form,
            "blueprint": blueprint,
        }
    )


@csrf_protect
@router.get("/ui/blueprints/delete/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/blueprints/delete/{blueprint_name}", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_blueprint_delete(
        blueprint_name: str,
        request: Request,
        session: Session = Depends(get_session)
):
    blueprint = session.get_one(TinyBlueprint, blueprint_name)

    form = await DeleteBlueprintForm.from_formdata(request)
    form.name.label.text = f"Type '{blueprint.name}' to confirm"
    form.name.validators = [DataRequired(), AnyOf([blueprint.name])]

    if await form.validate_on_submit():
        try:
            session.delete(blueprint)
            session.commit()
        except IntegrityError as e:
            if isinstance(e.orig, psycopg2.errors.IntegrityError):
                raise TinyPKIError(400, TinyPKIErrorReason.UNABLE_TO_DELETE_RESOURCE_HAS_DEPENDENCIES)
            else:
                raise e

        return RedirectResponse("/ui/blueprints", status_code=302)

    return templates.TemplateResponse(
        "blueprint_delete.html",
        {
            "request": request,
            "form": form,
            "blueprint": blueprint,
        }
    )
