import re
from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlmodel import Session, select, or_, and_

from ..config import CERTS_PER_PAGE
from ..dbmodels.stepca import X509Certificate


def common_list_x509_certificates(
        session: Session,
        search: Optional[str],
        page_no: Optional[int],
        cutoff: Optional[str]
):
    if not search:
        search = ""

    if page_no == 1:
        cutoff = None

    count_certificates = session.scalar(build_list_certificates_query(
        page_no=page_no,
        search=search,
        cutoff=cutoff,
        count=True
    ))
    certificates = session.exec(build_list_certificates_query(
        page_no=page_no,
        search=search,
        cutoff=cutoff,
        count=False
    )).all()

    if page_no == 1:
        if len(certificates) > 0:
            cutoff = certificates[0].indexed_at.isoformat()
        else:
            cutoff = None

    return cutoff, count_certificates, certificates


def build_list_certificates_query(*, page_no: Optional[int], search: Optional[str], cutoff: Optional[str],
                                  count: bool):
    if count:
        query = select(func.count()).select_from(X509Certificate)
    else:
        query = select(X509Certificate)

    if cutoff:
        cond_start_id = X509Certificate.indexed_at <= datetime.fromisoformat(cutoff)
    else:
        cond_start_id = True

    cond_search = True

    if search.strip() != "":
        alt_q = False

        if re.match(r'^([0-9a-fA-F]+)$', search):
            try:
                alt_q = (X509Certificate.serial_no == str(int(search, 16)))
            except TypeError:
                pass

        search_term = f"%{search}%"
        cond_search = or_(
            X509Certificate.subject_name.ilike(search_term),
            func.array_to_string(X509Certificate.subject_alt_names, ' ').ilike(search_term),
            X509Certificate.serial_no == search,
            alt_q,
            X509Certificate.fingerprint_sha256 == search
        )

    query = query.where(
        and_(
            cond_start_id,
            cond_search
        )
    )

    if not count:
        if not page_no:
            page_no = 1

        query = query.order_by(X509Certificate.indexed_at.desc())
        query = query.offset((page_no - 1) * CERTS_PER_PAGE).limit(CERTS_PER_PAGE)

    return query
