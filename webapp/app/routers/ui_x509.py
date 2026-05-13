import datetime
import math
import traceback
from typing import Optional

from fastapi import APIRouter, Request, Query, Depends
from flatten_dict import flatten
from sqlalchemy.exc import NoResultFound
from sqlmodel import Session, select
from starlette.responses import HTMLResponse, RedirectResponse
from starlette_wtf import csrf_protect
from wtforms.validators import AnyOf, DataRequired

from ..config import CERTS_PER_PAGE
from ..dbmodels.stepca import X509Certificate
from ..dependencies import get_session, templates
from ..forms.x509_revoke import X509RevokeForm
from ..internal.exc import NoCertificateToRevoke, RevokeReqStalledError, NoDefaultProvisioner, TinyPKIError, \
    TinyPKIErrorReason
from ..internal.x509_list_query import common_list_x509_certificates
from ..internal.x509_revoke import common_revoke
from ..stepapi.revoke import RevocationReason

router = APIRouter()


@router.get("/ui/x509/certificates", response_class=HTMLResponse, include_in_schema=False)
def route_list_x509_certificates(
        request: Request,
        search: Optional[str] = Query(None, description="Search by subject name or alt names"),
        page_no: Optional[int] = Query(1, description="Page number"),
        cutoff: Optional[str] = Query(None, description="Cutoff time (dont include certificates younger than the specified time)"),
        session: Session = Depends(get_session)
):
    cutoff, count_certificates, certificates = common_list_x509_certificates(session, search, page_no, cutoff)
    now = datetime.datetime.now().replace(tzinfo=None)

    return templates.TemplateResponse(
        "x509_certificates.html",
        {
            "request": request,
            "certificates": certificates,
            "search": search if search else "",
            "count": len(certificates),
            "now": now,
            "page_no": page_no,
            "page_count": math.ceil(count_certificates / CERTS_PER_PAGE),
            "cutoff": cutoff
        }
    )


@csrf_protect
@router.get("/ui/x509/certificate/{serial_no}", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/x509/certificate/{serial_no}", response_class=HTMLResponse, include_in_schema=False)
async def route_x509_certificate(
        request: Request,
        serial_no: str,
        session: Session = Depends(get_session)
):
    try:
        cert = session.exec(
            select(X509Certificate)
            .where(X509Certificate.serial_no == serial_no)
        ).one()
    except NoResultFound:
        raise TinyPKIError(status_code=404, reason=TinyPKIErrorReason.OBJECT_NOT_FOUND)

    raw_issuance_data = None

    if cert.x509_cert_data:
        raw_issuance_data = flatten(cert.x509_cert_data.raw_issuance_data, reducer='dot')

    return templates.TemplateResponse(
        "x509_certificate.html",
        {
            "request": request,
            "cert": cert,
            "raw_issuance_data": raw_issuance_data,
            "revocation_reasons": RevocationReason,
        }
    )


async def _process_revoke_form(
        session: Session,
        serial_no: str,
        form: X509RevokeForm,
):
    if serial_no != form.serial_no.data:
        raise TinyPKIError(status_code=400, reason=TinyPKIErrorReason.REVOKE_MISMATCHED_SERIAL)

    if serial_no != form.confirm_serial_no.data:
        raise TinyPKIError(status_code=400, reason=TinyPKIErrorReason.REVOKE_MISMATCHED_SERIAL)

    try:
        await common_revoke(session, serial_no, RevocationReason[form.reason.data])
    except NoDefaultProvisioner:
        raise TinyPKIError(status_code=404, reason=TinyPKIErrorReason.NO_DEFAULT_PROVISIONER)
    except NoCertificateToRevoke:
        raise TinyPKIError(status_code=404, reason=TinyPKIErrorReason.REVOKE_NO_CERT_FOUND)
    except RevokeReqStalledError:
        raise TinyPKIError(status_code=500, reason=TinyPKIErrorReason.REVOKE_REQ_STALLED)
    except RuntimeError:
        traceback.print_exc()
        raise TinyPKIError(status_code=500, reason=TinyPKIErrorReason.REVOKE_GENERIC_ERR)

    return RedirectResponse("/ui/x509/certificate/" + serial_no, status_code=302)


@csrf_protect
@router.get("/ui/x509/certificate/{serial_no}/revoke", response_class=HTMLResponse, include_in_schema=False)
@router.post("/ui/x509/certificate/{serial_no}/revoke", response_class=HTMLResponse, include_in_schema=False)
async def route_ui_x509_certificate_revoke(
        serial_no: str,
        request: Request,
        session: Session = Depends(get_session)
):
    try:
        cert = session.exec(
            select(X509Certificate)
            .where(X509Certificate.serial_no == serial_no)
        ).one()
    except NoResultFound:
        raise TinyPKIError(status_code=404, reason=TinyPKIErrorReason.OBJECT_NOT_FOUND)

    form = await X509RevokeForm.from_formdata(request)
    form.confirm_serial_no.label.text = f"Type '{cert.serial_no}' to confirm"
    form.confirm_serial_no.validators = [DataRequired(), AnyOf([cert.serial_no])]

    if await form.validate_on_submit():
        return await _process_revoke_form(session, serial_no, form)

    return templates.TemplateResponse(
        "x509_certificate_revoke.html",
        {
            "request": request,
            "form": form,
            "cert": cert,
        }
    )
