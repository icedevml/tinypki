import json

import httpx
import jwcrypto.jwa
from aiocache import cached
from jwcrypto import jwe
from jwcrypto.jwk import JWK

from .ca_fingerprint import get_step_ca_verify
from ..config import TINYPKI_STEP_CA_URL, PUBLIC_PROXY_CACHE_INTERVAL
from ..internal.duration import parse_go_duration
from ..internal.exc import ProvisionerNotFound

# Step CA wrapped JWK tokens use 60k PBKDF2 iterations by default
jwcrypto.jwa.default_max_pbkdf2_iterations = 600000


def decrypt_jwk(token: str, password: str) -> dict:
    jwetoken = jwe.JWE()
    jwetoken.deserialize(token, key=JWK.from_password(password))
    return json.loads(jwetoken.payload)


async def get_provisioner_record(provisioner_name: str) -> dict | None:
    cursor = None

    async with httpx.AsyncClient(verify=await get_step_ca_verify()) as client:
        while True:
            res = await client.get(TINYPKI_STEP_CA_URL + "/provisioners", params={"cursor": cursor})
            await res.aread()
            res.raise_for_status()

            out = res.json()
            for provisioner in out["provisioners"]:
                if provisioner.get("type") == "JWK" and provisioner.get("name") == provisioner_name:
                    return provisioner

            cursor = out["nextCursor"]

            if not cursor:
                break


async def get_provisioner_jwk(provisioner_name: str, *, password: str | None = None,
                              pwd_file: str | None = None) -> dict:
    provisioner = await get_provisioner_record(provisioner_name)

    if not provisioner:
        raise ProvisionerNotFound("Provisioner not found.")

    if password and pwd_file:
        raise ValueError("Both password and pwd_file provided.")

    if pwd_file:
        with open(pwd_file, "r") as f:
            password = f.read().strip()

    provisioner["jwk"] = decrypt_jwk(provisioner["encryptedKey"], password)
    return provisioner


@cached(ttl=PUBLIC_PROXY_CACHE_INTERVAL)
async def get_provisioner_max_days(provisioner_name: str) -> int:
    provisioner = await get_provisioner_record(provisioner_name)

    if not provisioner:
        raise ValueError("Provisioner not found.")

    max_duration_str = provisioner.get("claims", {}).get("maxTLSCertDuration", "24h")
    max_duration_f = parse_go_duration(max_duration_str)
    return int(max_duration_f) // (60*60*24)
