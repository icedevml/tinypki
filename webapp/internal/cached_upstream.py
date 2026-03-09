import datetime

import httpx
from aiocache import cached
from pydantic import BaseModel

from ..config import TINYPKI_STEP_CA_URL, PUBLIC_PROXY_CACHE_INTERVAL
from ..stepapi.ca_fingerprint import get_step_ca_verify


class CachedUpstreamResponse(BaseModel):
    time_generated: datetime.datetime
    status_code: int
    type: str
    body: bytes


@cached(ttl=PUBLIC_PROXY_CACHE_INTERVAL)
async def cached_upstream_request(path: str):
    async with httpx.AsyncClient(verify=await get_step_ca_verify()) as client:
        req = client.build_request("GET", TINYPKI_STEP_CA_URL + path)
        res = await client.send(req, stream=True)
        res.raise_for_status()
        content = await res.aread()
        await res.aclose()
        return CachedUpstreamResponse(
            time_generated=datetime.datetime.now(datetime.timezone.utc),
            status_code=res.status_code,
            type=res.headers.get("content-type"),
            body=content
        )
