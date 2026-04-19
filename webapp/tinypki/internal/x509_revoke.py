import time

from sqlalchemy.exc import NoResultFound
from sqlmodel import Session, select

from .default_jwk import get_default_jwk_provisioner
from ..dbmodels.stepca import X509Certificate, X509CertificateRevocation
from ..internal.exc import NoCertificateToRevoke, RevokeReqStalledError
from ..stepapi.revoke import RevocationReason, revoke_cert


async def common_revoke(session: Session, serial_no: str, reason: RevocationReason):
    try:
        session.exec(select(X509Certificate).where(X509Certificate.serial_no == serial_no)).one()
    except NoResultFound:
        raise NoCertificateToRevoke()

    provisioner = get_default_jwk_provisioner(session)
    await revoke_cert(provisioner, serial_no, reason=reason)

    # poll if we've already indexed that the certificate was revoked
    for _ in range(20):
        time.sleep(0.5)

        try:
            session.exec(
                select(X509CertificateRevocation)
                .where(X509CertificateRevocation.serial_no == serial_no)
            ).one()
            break
        except NoResultFound:
            pass
    else:
        raise RevokeReqStalledError()
