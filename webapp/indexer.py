import binascii
import json
import re
import time
from datetime import datetime, timezone
from enum import Enum

import httpx
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import KeyUsage, ExtendedKeyUsage
from pgmq import PGMQueue, Message
from sqlalchemy.exc import NoResultFound
from sqlmodel import Session, select

from app.config import POSTGRES_PASSWORD, POSTGRES_USER, TINYPKI_STEP_CA_URL, PG_HOST, PG_PORT, LOG_JSON_FORMAT, \
    LOG_LEVEL, LOG_NAME_INDEXER
from app.custom_logger import setup_logging
from app.dbmodels.stepca import X509Certificate, X509CertificateRevocation, X509CertificateData, ACMECert, ACMEAccount
from app.dbmodels.tinypki import TinySystemMetadata
from app.dependencies import engine
from app.internal.san_utils import unmap_sans

setup_logging(json_logs=LOG_JSON_FORMAT, log_level=LOG_LEVEL)
app_logger = structlog.stdlib.get_logger(LOG_NAME_INDEXER)


def check_stepca_healthy():
    app_logger.info("Waiting for Step CA to become healthy...")

    for _ in range(100):
        try:
            res = httpx.get(TINYPKI_STEP_CA_URL + "/health", timeout=5, verify=False)
            res.raise_for_status()
            break
        except httpx.HTTPError as e:
            app_logger.warn("Failed to connect to stepca. " + e.__class__.__name__ + ": " + str(e))
            pass

        time.sleep(1.0)
    else:
        raise RuntimeError("Failed to connect to stepca.")


check_stepca_healthy()

queue = PGMQueue(
    host=PG_HOST,
    port=PG_PORT,
    username=POSTGRES_USER,
    password=POSTGRES_PASSWORD,
    database="stepca"
)


class DataFormat(Enum):
    BYTES = 1
    UTF8 = 2
    JSON = 3


def parse(val: str, fmt: DataFormat = DataFormat.BYTES):
    if not re.match(r'^\\x([0-9a-f]+)$', val):
        raise RuntimeError("Malformed data, expected PostgreSQL hex string.")

    out = binascii.unhexlify(val[2:])

    if fmt == DataFormat.BYTES:
        return out
    elif fmt == DataFormat.UTF8:
        return out.decode('utf-8')
    elif fmt == DataFormat.JSON:
        return json.loads(out)
    else:
        raise RuntimeError('Unsupported format provided.')


def update_state(data: dict):
    with Session(engine) as session:
        full_data = {}
        full_data.update(data)
        full_data.update({"ts": datetime.now(timezone.utc).isoformat()})

        sync_state = session.get(TinySystemMetadata, "sync_state")
        sync_state.value = full_data
        session.add(sync_state)
        session.commit()


def find_id_by_serial(session: Session, model, serial_dec_str: str):
    try:
        found_obj = session.exec(
            select(model)
            .where(model.serial_no == serial_dec_str)
        ).one()
    except NoResultFound:
        return None

    return found_obj.id


def find_id_by_object_id(session: Session, model, object_id_dec_str: str):
    try:
        found_obj = session.exec(
            select(model)
            .where(model.object_id == object_id_dec_str)
        ).one()
    except NoResultFound:
        return None

    return found_obj.id


def _get_ku(cert: x509.Certificate) -> list[str]:
    ku_attrs = [
        ["digital_signature", "digitalSignature", []],
        ["content_commitment", "nonRepudiation", []],
        ["key_encipherment", "keyEncipherment", []],
        ["data_encipherment", "dataEncipherment", []],
        ["key_agreement", "keyAgreement", []],
        ["key_cert_sign", "keyCertSign", []],
        ["crl_sign", "cRLSign", []],
        ["encipher_only", "encipherOnly", ["key_agreement"]],
        ["decipher_only", "decipherOnly", ["key_agreement"]]
    ]

    try:
        ext = cert.extensions.get_extension_for_class(KeyUsage)
    except x509.ExtensionNotFound:
        return []

    out = []

    for ku_attr in ku_attrs:
        orig_name, store_name, deps = ku_attr
        skip = False

        for dep in deps:
            if not getattr(ext.value, dep):
                skip = True

        if not skip and getattr(ext.value, orig_name):
            out.append(store_name)

    return out


def _get_eku(cert: x509.Certificate):
    try:
        ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return []

    out = []

    for eku_attr in ext.value:
        if eku_attr._name:
            out.append(eku_attr._name)
        else:
            out.append(eku_attr.dotted_string)

    return out


def process_x509_cert(serial_dec_str, nvalue, initial_sync):
    cert_der_b = parse(nvalue, fmt=DataFormat.BYTES)
    cert = x509.load_der_x509_certificate(cert_der_b)

    if str(cert.serial_number) != serial_dec_str:
        raise RuntimeError('Mismatched serial number: ' + str(cert.serial_number) + ' vs ' + serial_dec_str)

    key_usage = _get_ku(cert)
    ext_key_usage = _get_eku(cert)
    sans = unmap_sans(cert)

    with Session(engine) as session:
        if initial_sync == "in_progress":
            indexed_at = cert.not_valid_before_utc
        else:
            indexed_at = datetime.now(timezone.utc)

        orm_obj = X509Certificate(
            serial_no=serial_dec_str,
            indexed_at=indexed_at,
            subject_name=cert.subject.rfc4514_string(),
            subject_alt_names=sans,
            key_usage=key_usage,
            ext_key_usage=ext_key_usage,
            issuer_name=cert.issuer.rfc4514_string(),
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            time_not_before=cert.not_valid_before_utc.replace(tzinfo=timezone.utc),
            time_not_after=cert.not_valid_after_utc.replace(tzinfo=timezone.utc),
            cert_pem=cert.public_bytes(Encoding.PEM).decode('ascii')
        )

        session.merge(orm_obj)
        session.commit()


def process_x509_certs_data(serial_dec_str, nvalue):
    data = parse(nvalue, fmt=DataFormat.JSON)

    with Session(engine) as session:
        orm_obj = X509CertificateData(
            serial_no=serial_dec_str,
            provisioner_id=data["provisioner"]["id"],
            provisioner_name=data["provisioner"]["name"],
            provisioner_type=data["provisioner"]["type"],
            raw_issuance_data=data
        )

        session.merge(orm_obj)
        session.commit()


def process_acme_cert(serial_dec_str, nvalue):
    data = parse(nvalue, fmt=DataFormat.JSON)

    with Session(engine) as session:
        orm_obj = ACMECert(
            id=find_id_by_object_id(session, ACMECert, serial_dec_str),
            object_id=serial_dec_str,
            data=data
        )

        session.merge(orm_obj)
        session.commit()


def process_acme_account(serial_dec_str, nvalue):
    data = parse(nvalue, fmt=DataFormat.JSON)

    with Session(engine) as session:
        orm_obj = ACMEAccount(
            id=find_id_by_object_id(session, ACMEAccount, serial_dec_str),
            object_id=serial_dec_str,
            data=data
        )

        session.merge(orm_obj)
        session.commit()


def process_revoked_x509_cert(serial_dec_str, nvalue):
    data = parse(nvalue, fmt=DataFormat.JSON)

    if data["Serial"] != serial_dec_str:
        raise RuntimeError('Mismatched serial number: ' + data["Serial"] + ' vs ' + serial_dec_str)

    with Session(engine) as session:
        orm_obj = X509CertificateRevocation(
            id=find_id_by_serial(session, X509CertificateRevocation, serial_dec_str),
            serial_no=serial_dec_str,
            provisioner_id=data["ProvisionerID"],
            reason_code=data["ReasonCode"],
            reason=data["Reason"],
            revoked_at=datetime.fromisoformat(data["RevokedAt"]).astimezone(timezone.utc),
            expires_at=datetime.fromisoformat(data["ExpiresAt"]).astimezone(timezone.utc),
            token_id=data["TokenID"],
            mtls=data["MTLS"],
            acme=data["ACME"]
        )

        session.merge(orm_obj)
        session.commit()


def run():
    app_logger.info("Starting indexer...")
    initial_sync = True

    while True:
        read_messages: list[Message] = queue.read_with_poll(
            "event_queue", vt=15, poll_interval_ms=100, max_poll_seconds=5, qty=100
        )
        for envelope in read_messages:
            data = envelope.message['data']
            initial_sync = envelope.message['initial_sync_state']['state']

            serial_dec_str = parse(data["nkey"], fmt=DataFormat.UTF8)

            if envelope.message['table'] == 'x509_certs':
                process_x509_cert(serial_dec_str, data["nvalue"], initial_sync)
            elif envelope.message['table'] == 'x509_certs_data':
                process_x509_certs_data(serial_dec_str, data["nvalue"])
            elif envelope.message['table'] == 'acme_certs':
                process_acme_cert(serial_dec_str, data["nvalue"])
            elif envelope.message['table'] == 'acme_accounts':
                process_acme_account(serial_dec_str, data["nvalue"])
            elif envelope.message['table'] == 'revoked_x509_certs':
                process_revoked_x509_cert(serial_dec_str, data["nvalue"])

            queue.archive("event_queue", envelope.msg_id)

        oldest_msg = queue.metrics("event_queue").oldest_msg_age_sec

        if oldest_msg and oldest_msg > 60:
            update_state({"state": "unhealthy"})
            app_logger.warn(f"Unhealthy state, can't keep up with the message flow!",
                            oldest_msg_age_sec=oldest_msg)
        else:
            update_state({"state": "healthy"})

        metrics = queue.metrics("event_queue")

        if initial_sync or len(read_messages) > 0:
            initial_sync = False

            app_logger.info(f"Synchronized objects.", synced_objects=len(read_messages))

            if metrics.queue_length == 0:
                app_logger.info(f"Sync OK. Queue is empty.")
            elif metrics.queue_length > 0:
                app_logger.info(f"Sync in progress...", queue_length=metrics.queue_length)


if __name__ == "__main__":
    run()
