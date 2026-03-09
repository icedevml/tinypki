import base64
from contextlib import asynccontextmanager
from datetime import datetime
from datetime import timezone, timedelta
from urllib.parse import unquote

from aiocache import cached
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlmodel import SQLModel
from sqlmodel import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse, RedirectResponse
from starlette_wtf import CSRFProtectMiddleware

from .config import PROXY_AUTH_TOKEN, CLIENT_CERT_REVALIDATE_INTERVAL
from .config import TINYPKI_ALLOW_CERTS, SESSION_MIDDLEWARE_KEY, CSRF_PROTECT_MIDDLEWARE_KEY, \
    UNSAFE_OVERRIDE_CLIENT_CN
from .dbmodels.tinypki import TinySystemMetadata
from .dependencies import templates, engine
from .internal.cached_upstream import cached_upstream_request
from .internal.exc import TinyPKIError, TinyPKIErrorReason
from .routers import public_api_proxy, public_api_redeem, api_x509, ui_invitations, ui_provisioners, ui_x509, \
    public_ui_redeem, ui_blueprints
from .stepapi.client_validator import validate_client_cert


@asynccontextmanager
async def app_lifespan(_app: FastAPI):
    def create_sync_state():
        SQLModel.metadata.create_all(engine)

        with Session(engine) as session:
            stmt = pg_insert(TinySystemMetadata).values(
                key="sync_state",
                value={}
            ).on_conflict_do_nothing(index_elements=['key'])

            session.exec(stmt)
            session.commit()

    def close_psycopg():
        import gc
        import psycopg_pool
        [obj.close() for obj in gc.get_objects() if isinstance(obj, psycopg_pool.ConnectionPool)]

    # before app
    create_sync_state()

    yield

    # after app
    close_psycopg()


app = FastAPI(docs_url="/public/docs", lifespan=app_lifespan)


@app.exception_handler(TinyPKIError)
async def tinypkierror_exception_handler(request: Request, exc: TinyPKIError):
    return exc.serialize(request)


@cached(ttl=CLIENT_CERT_REVALIDATE_INTERVAL)
async def get_forwarded_client_cert(x_client_cert: str):
    print('[!] Revalidating forwarded client certificate...')
    if not x_client_cert or not x_client_cert.strip():
        # empty or all-whitespace character
        return None

    if x_client_cert == "{http.request.tls.client.certificate_der_base64}":
        # placeholder leftover from Caddy, indicates that there was no client certificate presented
        return None

    if '%' in x_client_cert:
        # URL Encoded PEM format (nginx)
        cert_b = load_pem_x509_certificate(unquote(x_client_cert).encode('ascii')).public_bytes(Encoding.DER)
    else:
        # Base64 DER encoded (Caddy)
        cert_b = base64.b64decode(x_client_cert)

    cached_crl = await cached_upstream_request("/1.0/crl")
    return await validate_client_cert(cert_b, cached_crl.body)


@app.middleware("http")
async def check_indexer_healthy(request: Request, call_next):
    if request.url.path.startswith("/public/"):
        return await call_next(request)

    with Session(engine) as session:
        sync_state_record = session.get(TinySystemMetadata, "sync_state")
        val = sync_state_record.value

        if not val or val.get("state") != "healthy" or datetime.now(timezone.utc) - datetime.fromisoformat(
                val["ts"]) > timedelta(seconds=60):
            return TinyPKIError(503, TinyPKIErrorReason.INDEXER_UNHEALTHY).serialize(request)

    return await call_next(request)


@app.middleware("http")
async def annotate_request_state(request: Request, call_next):
    request.state.render_html_exceptions = True
    request.state.display_admin_ui = False

    if not request.url.path.startswith("/public/") and request.state.auth_client_cert:
        request.state.display_admin_ui = True

    if request.url.path.startswith("/public/api/"):
        request.state.render_html_exceptions = False
    elif request.url.path.startswith("/api/"):
        request.state.render_html_exceptions = False

    return await call_next(request)


@app.middleware("http")
async def check_client_cert(request: Request, call_next):
    request.state.is_debug = False
    request.state.auth_client_cert = None

    if request.url.path.startswith("/public/") or request.url.path == "/code":
        return await call_next(request)

    allowed = False

    if not UNSAFE_OVERRIDE_CLIENT_CN:
        proxy_auth = request.headers.get("x-proxy-auth")
        client_cert = request.headers.get("x-client-cert")

        if not PROXY_AUTH_TOKEN or len(PROXY_AUTH_TOKEN) < 16:
            raise RuntimeError("PROXY_AUTH_TOKEN must be set and must be at least 16 characters long.")
        elif PROXY_AUTH_TOKEN != proxy_auth:
            raise RuntimeError("Incorrect X-Proxy-Auth provided.")

        request.state.is_debug = False
        request.state.auth_client_cert = await get_forwarded_client_cert(client_cert)
    else:
        request.state.is_debug = True
        request.state.auth_client_cert = dict(UNSAFE_OVERRIDE_CLIENT_CN)

    print("[!] Client cert", request.state.auth_client_cert)

    if request.state.auth_client_cert:
        cn = request.state.auth_client_cert["Common Name"]

        if cn in TINYPKI_ALLOW_CERTS:
            allowed = True

    if not allowed:
        if request.state.auth_client_cert and request.state.auth_client_cert.get("Common Name"):
            error_code = "AUTH_CLIENT_CERT_NOT_ALLOWED"
            error_msg = (f"The user CN={request.state.auth_client_cert["Common Name"]} is not allowed to use TinyPKI. "
                         f"Check if the user is allowlisted in TINYPKI_ALLOW_CERTS environment variable.")
        else:
            error_code = "AUTH_NO_CLIENT_CERT"
            error_msg = "Client certificate is required to use TinyPKI, although no certificate was presented."

        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": {"code": error_code, "message": error_msg}}, status_code=401)
        else:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "message": error_msg
                },
                status_code=401
            )

    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
    }

    response = await call_next(request)
    response.headers.update(headers)
    return response


app.mount("/public/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def route_main():
    return RedirectResponse("/ui/x509/certificates")


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def route_ui():
    return RedirectResponse("/ui/x509/certificates")


# shorthand for /public/ui/redeem
@app.get("/code", response_class=HTMLResponse, include_in_schema=False)
def route_code():
    return RedirectResponse("/public/ui/redeem")


app.add_middleware(SessionMiddleware, secret_key=SESSION_MIDDLEWARE_KEY)
app.add_middleware(CSRFProtectMiddleware, csrf_secret=CSRF_PROTECT_MIDDLEWARE_KEY)

# endpoints starting with /public/ are available without authentication
app.include_router(public_api_proxy.router)
app.include_router(public_api_redeem.router)
app.include_router(public_ui_redeem.router)

# API for authenticated users
app.include_router(api_x509.router)

# UI for authenticated users
app.include_router(ui_blueprints.router)
app.include_router(ui_invitations.router)
app.include_router(ui_provisioners.router)
app.include_router(ui_x509.router)
