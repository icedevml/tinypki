import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum

import httpx
import jwt
from jwt.algorithms import ECAlgorithm

from .ca_fingerprint import get_step_ca_verify
from ..config import TINYPKI_STEP_CA_URL


class CertAlreadyRevokedError(RuntimeError):
    pass


class RevocationReason(Enum):
    unused = 0
    keyCompromise = 1
    cACompromise = 2
    affiliationChanged = 3
    superseded = 4
    cessationOfOperation = 5
    certificateHold = 6
    privilegeWithdrawn = 7
    aACompromise = 8


async def revoke_cert(provisioner: dict, serial_no: str, reason: RevocationReason):
    jwt_body = {
        "aud": TINYPKI_STEP_CA_URL + "/1.0/revoke",
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=5),
        "iat": datetime.now(tz=timezone.utc),
        "nbf": datetime.now(tz=timezone.utc),
        "jti": str(uuid.uuid4()),
        "iss": provisioner["name"],
        "sub": serial_no,
    }

    key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(provisioner["jwk"])
    ott = jwt.encode(
        jwt_body,
        key=key,
        headers={"kid": provisioner["jwk"]["kid"]},
        algorithm="ES256"
    )

    async with httpx.AsyncClient(verify=await get_step_ca_verify()) as client:
        res = await client.post(TINYPKI_STEP_CA_URL + "/1.0/revoke", json={
            "serial": serial_no,
            "reason": reason.name,
            "reasonCode": reason.value,
            "passive": True,
            "ott": ott
        })
        await res.aread()

        if res.status_code == 400:
            out = res.json()

            if "already revoked" in out["message"]:
                raise CertAlreadyRevokedError("Certificate is already revoked.")

        res.raise_for_status()
        out = res.json()

    if out["status"] != "ok":
        raise RuntimeError("Unexpected status: " + out)
