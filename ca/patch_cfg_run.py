import json
import os

from common_boolutil import strtobool2
from common_cfg import cfg_patch_db, cfg_patch_remote_admin

CONFIGPATH = os.environ["CONFIGPATH"]

DOCKER_TINYPKI_CRL_ENABLE = os.environ.get("DOCKER_TINYPKI_CRL_ENABLE", "1")
DOCKER_TINYPKI_CRL_IDP_URL = os.environ.get("DOCKER_TINYPKI_CRL_IDP_URL")
DOCKER_TINYPKI_CRL_GENERATE_ON_REVOKE = os.environ.get("DOCKER_TINYPKI_CRL_GENERATE_ON_REVOKE")
DOCKER_TINYPKI_CRL_CACHE_DURATION = os.environ.get("DOCKER_TINYPKI_CRL_CACHE_DURATION")
DOCKER_TINYPKI_CRL_RENEW_PERIOD = os.environ.get("DOCKER_TINYPKI_CRL_RENEW_PERIOD")

DOCKER_TINYPKI_CRL_ENABLE = strtobool2(DOCKER_TINYPKI_CRL_ENABLE)

if DOCKER_TINYPKI_CRL_GENERATE_ON_REVOKE is not None:
    DOCKER_TINYPKI_CRL_GENERATE_ON_REVOKE = strtobool2(DOCKER_TINYPKI_CRL_GENERATE_ON_REVOKE)

with open(CONFIGPATH, "r") as f:
    config = json.loads(f.read())

config = cfg_patch_db(config)
config = cfg_patch_remote_admin(config)

config["crl"] = {
    "enabled": DOCKER_TINYPKI_CRL_ENABLE
}

if DOCKER_TINYPKI_CRL_ENABLE:
    config["crl"]["generateOnRevoke"] = DOCKER_TINYPKI_CRL_GENERATE_ON_REVOKE

    if DOCKER_TINYPKI_CRL_CACHE_DURATION:
        config["crl"]["cacheDuration"] = DOCKER_TINYPKI_CRL_CACHE_DURATION

    if DOCKER_TINYPKI_CRL_RENEW_PERIOD:
        config["crl"]["renewPeriod"] = DOCKER_TINYPKI_CRL_RENEW_PERIOD

    if DOCKER_TINYPKI_CRL_IDP_URL:
        config["crl"]["idpURL"] = DOCKER_TINYPKI_CRL_IDP_URL

# write patched config
with open(CONFIGPATH, "w") as f:
    f.write(json.dumps(config, indent=4))

print("[!] Finished patch_cfg_run.py")
