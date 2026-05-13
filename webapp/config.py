import binascii
import json
import os
import re

from dotenv import load_dotenv
from pydantic import TypeAdapter

base = os.path.dirname(os.path.abspath(__file__))

load_dotenv(dotenv_path=os.path.join(base, "../env/db.env"))
load_dotenv(dotenv_path=os.path.join(base, "../env/tinypki.env"))
load_dotenv(dotenv_path=os.path.join(base, "../env/caddy.env"))


class _NoArg:
    """A sentinel value to indicate that a parameter was not given"""


NO_ARG = _NoArg()


def get_env_var(key: str, default: str | _NoArg = NO_ARG) -> str:
    """Get an environment variable, raise an error if it is missing and no default is given."""
    try:
        return os.environ[key]
    except KeyError:
        if isinstance(default, _NoArg):
            raise ValueError(f"Environment variable {key} is missing")

        return default


def strtobool(val: str) -> bool:
    return TypeAdapter(bool).validate_python(val)


def parse_list(var_name):
    data = os.environ[var_name]

    out = map(lambda v: v.strip(), data.split(","))
    out = filter(lambda v: len(v) > 0, out)

    return list(out)


def parse_fingerprint(var_name):
    data = os.environ[var_name]

    if not data or not data.strip():
        return ""

    if re.match(r"^[0-9a-fA-F]{64}$", data):
        return data

    raise ValueError(f"Incorrect value in {var_name}. The fingerprint should either be left empty or"
                     f"should be a 64 character hexadecimal string.")


LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_JSON_FORMAT = strtobool(os.environ.get("LOG_JSON_FORMAT", "false"))
LOG_NAME = "tinypki.app_logs"
LOG_NAME_INDEXER = "tinypki.indexer_logs"
LOG_NAME_REINDEX = "tinypki.reindex_logs"
LOG_ACCESS_NAME = "tinypki.access_logs"
LOG_INCLUDE_STACK = True

POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
PG_HOST = os.environ["PG_HOST"]
PG_PORT = int(os.environ["PG_PORT"])

SQLALCHEMY_DATABASE_URL = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{PG_HOST}:{PG_PORT}/tinypki"
)
SQLALCHEMY_ECHO = get_env_var("SQLALCHEMY_ECHO", "") == "true"

ATREST_ENCRYPTION_KEY = os.environ["ATREST_ENCRYPTION_KEY"]
SESSION_MIDDLEWARE_KEY = os.environ["SESSION_MIDDLEWARE_KEY"]
CSRF_PROTECT_MIDDLEWARE_KEY = os.environ["CSRF_PROTECT_MIDDLEWARE_KEY"]
PROXY_AUTH_TOKEN = os.environ.get("PROXY_AUTH_TOKEN")
CERTS_PER_PAGE = int(os.environ["CERTS_PER_PAGE"])
PUBLIC_PROXY_CACHE_INTERVAL = int(os.environ["PUBLIC_PROXY_CACHE_INTERVAL"])
CLIENT_CERT_REVALIDATE_INTERVAL = int(os.environ["CLIENT_CERT_REVALIDATE_INTERVAL"])
TINYPKI_ALLOW_CERTS = parse_list("TINYPKI_ALLOW_CERTS")
TINYPKI_DISALLOWED_NAMES = parse_list("TINYPKI_DISALLOWED_NAMES")
TINYPKI_STEP_CA_URL = os.environ["TINYPKI_STEP_CA_URL"]
TINYPKI_STEP_CA_ROOT_FINGERPRINT = parse_fingerprint("TINYPKI_STEP_CA_ROOT_FINGERPRINT")
PBKDF2_SALT = binascii.unhexlify(os.environ["PBKDF2_SALT"])
PBKDF2_ITERATIONS = int(os.environ["PBKDF2_ITERATIONS"])
UNSAFE_OVERRIDE_CLIENT_CN = None

if os.environ.get("UNSAFE_OVERRIDE_CLIENT_CN"):
    UNSAFE_OVERRIDE_CLIENT_CN = json.loads(os.environ.get("UNSAFE_OVERRIDE_CLIENT_CN"))
