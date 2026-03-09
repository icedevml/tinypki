import io

from fastapi import APIRouter
from starlette.responses import StreamingResponse

from ..internal.cached_upstream import CachedUpstreamResponse, cached_upstream_request

router = APIRouter()


def _common_make_response(data: CachedUpstreamResponse):
    return StreamingResponse(
        io.BytesIO(data.body),
        status_code=data.status_code,
        headers={
            "Content-Type": data.type,
            "X-Time-Generated": data.time_generated.isoformat(),
        }
    )


@router.get(
    "/public/api/crl",
    response_class=StreamingResponse,
    summary="Download Certificate Revocation List (CRL)",
    responses={
        200: {
            "description": "DER-encoded Certificate Revocation List (RFC 5280). "
                           "Proxied and cached from the upstream Step CA.",
            "content": {"application/pkix-crl": {}},
        }
    }
)
async def route_public_api_crl():
    return _common_make_response(await cached_upstream_request("/1.0/crl"))


@router.get(
    "/public/api/roots.pem",
    response_class=StreamingResponse,
    summary="Download root CA certificate chain (PEM)",
    responses={
        200: {
            "description": "PEM-encoded root CA certificate(s). "
                           "May contain multiple certificates if there are multiple roots. "
                           "Proxied and cached from the upstream Step CA.",
            "content": {"application/x-pem-file": {"example": "-----BEGIN CERTIFICATE-----\nMIIBozCCAUqgA...\n-----END CERTIFICATE-----\n"}},
        }
    }
)
async def route_public_api_roots():
    return _common_make_response(await cached_upstream_request("/roots.pem"))


@router.get(
    "/public/api/intermediates.pem",
    response_class=StreamingResponse,
    summary="Download intermediate CA certificate chain (PEM)",
    responses={
        200: {
            "description": "PEM-encoded intermediate CA certificate(s). "
                           "May contain multiple certificates if there are multiple intermediates. "
                           "Proxied and cached from the upstream Step CA.",
            "content": {"application/x-pem-file": {"example": "-----BEGIN CERTIFICATE-----\nMIIBozCCAUqgA...\n-----END CERTIFICATE-----\n"}},
        }
    }
)
async def route_public_api_intermediates():
    return _common_make_response(await cached_upstream_request("/intermediates.pem"))
