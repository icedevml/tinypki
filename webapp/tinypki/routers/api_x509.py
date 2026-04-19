import math
import traceback
from enum import Enum
from typing import Optional, List

from fastapi import APIRouter, Query, Depends
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..config import CERTS_PER_PAGE
from ..dbmodels.stepca import X509CertificateRevocation, X509Certificate
from ..dependencies import get_session, SessionDep
from ..internal.exc import NoCertificateToRevoke, RevokeReqStalledError, TinyPKIError, TinyPKIErrorReason
from ..internal.exc import NoDefaultProvisioner
from ..internal.x509_list_query import common_list_x509_certificates
from ..internal.x509_revoke import common_revoke
from ..stepapi.revoke import RevocationReason, CertAlreadyRevokedError

router = APIRouter()


class PaginationInfo(BaseModel):
    page_no: int = Field(examples=[1])
    page_count: int = Field(examples=[1])
    cursor: str = Field(examples=["2026-02-26T14:44:10.454905"])


class CertificateListResult(BaseModel):
    count: int = Field(examples=[1])
    data: List[X509Certificate]


class CertificateListResponse(BaseModel):
    pages: PaginationInfo
    result: CertificateListResult


@router.get(
    "/api/x509/certs",
    response_model=CertificateListResponse,
    summary="List indexed X.509 certificates",
    responses={
        200: {"description": "Paginated list of X.509 certificates that were indexed from the Step CA"}
    }
)
def route_api_list_x509_certificates(
        search: Optional[str] = Query(
            None,
            description="Filter query (part of subject, part of subject alternative name, "
                        "full serial number or full sha256 fingerprint)"
        ),
        page_no: Optional[int] = Query(1, description="Page number (indexed from 1)"),
        cursor: Optional[str] = Query(
            None,
            description="ISO date string; only certificates issued on or after this date are returned. "
                        "Pass the value from a previous response to keep pagination stable across requests."),
        session: Session = Depends(get_session)
):
    """
    Return a paginated list of X.509 certificates.

    For the initially migrated data, results will be sorted by the certificate's "not before date".
    Newly issued certificates will be sorted by the actual date and time they were indexed at (usually right
    before issuance).

    Use `cursor` to anchor pagination — pass back the `cursor` value from the
    first response on subsequent page requests so new certificates issued in the
    meantime don't shift results.
    """
    cursor, count_certificates, certificates = common_list_x509_certificates(session, search, page_no, cursor)

    return CertificateListResponse(**{
        "pages": PaginationInfo(**{
            "page_no": page_no,
            "page_count": math.ceil(count_certificates / CERTS_PER_PAGE),
            "cursor": cursor
        }),
        "result": CertificateListResult(**{
            "count": count_certificates,
            "data": certificates,
        })
    })


class RevocationReasonKey(str, Enum):
    """RFC 5280 certificate revocation reason codes."""
    unused = "unused"
    keyCompromise = "keyCompromise"
    cACompromise = "cACompromise"
    affiliationChanged = "affiliationChanged"
    superseded = "superseded"
    cessationOfOperation = "cessationOfOperation"
    certificateHold = "certificateHold"
    privilegeWithdrawn = "privilegeWithdrawn"
    aACompromise = "aACompromise"


class RevocationRequestData(BaseModel):
    serial_no: str = Field(
        description="Certificate serial number in colon-separated hex",
        examples=["124455931156400799172400320153368118881"]
    )
    reason: RevocationReasonKey = Field(
        description="RFC 5280 revocation reason. Use 'keyCompromise' for private key exposure, "
                    "'cessationOfOperation' for routine decommission.",
        examples=[RevocationReasonKey.cessationOfOperation]
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"serial_no": "124455931156400799172400320153368118881", "reason": "keyCompromise"},
                {"serial_no": "82779304335531386946508913999602037863", "reason": "cessationOfOperation"},
            ]
        }
    }


class RevocationResponseData(BaseModel):
    status: str = Field(examples=["ok"])


@router.post(
    "/api/x509/revoke",
    response_model=RevocationResponseData,
    summary="Revoke an X.509 certificate",
    responses={
        200: {"description": "Certificate successfully revoked"},
        400: {"description": "Certificate is already revoked"},
        404: {"description": "Certificate not found, or no default provisioner configured"},
        500: {"description": "Generic revocation error, or revocation request stalled"},
    }
)
async def route_api_x509_revoke(
        data: RevocationRequestData,
        session: Session = Depends(get_session)
):
    """
    Revoke a certificate by serial number. The request will be forwarded to the Step CA, which will
    mark the certificate as revoked. It will start appearing as revoked in the CRL, starting with the next
    re-generation.
    """
    try:
        await common_revoke(session, data.serial_no, RevocationReason[data.reason.value])
    except CertAlreadyRevokedError:
        raise TinyPKIError(400, TinyPKIErrorReason.REVOKE_ALREADY_REVOKED)
    except NoDefaultProvisioner:
        raise TinyPKIError(404, TinyPKIErrorReason.NO_DEFAULT_PROVISIONER)
    except NoCertificateToRevoke:
        raise TinyPKIError(404, TinyPKIErrorReason.REVOKE_NO_CERT_FOUND)
    except RevokeReqStalledError:
        raise TinyPKIError(500, TinyPKIErrorReason.REVOKE_REQ_STALLED)
    except RuntimeError:
        traceback.print_exc()
        raise TinyPKIError(500, TinyPKIErrorReason.REVOKE_GENERIC_ERR)

    return RevocationResponseData(status="ok")


@router.get(
    "/api/x509/revoked",
    summary="List all revoked certificates"
)
def route_api_x509_revoked(session: SessionDep):
    """
    List all revoked certificates.
    """
    return session.exec(select(X509CertificateRevocation)).all()
