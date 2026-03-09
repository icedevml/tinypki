import json
import os
import subprocess
import time

import httpx

from common_cfg import cfg_patch_db, cfg_patch_remote_admin

CONFIGPATH = os.environ["CONFIGPATH"]
DOCKER_STEPCA_INIT_PROVISIONER_NAME = os.environ["DOCKER_STEPCA_INIT_PROVISIONER_NAME"]


def validate_provisioners(data):
    if len(data["provisioners"]) < 1:
        print("No provisioners found")
        return False

    first_provisioner = data["provisioners"][0]

    if first_provisioner["type"] != "JWK":
        print("Unexpected first provisioner type")
        return False

    if first_provisioner["name"] != DOCKER_STEPCA_INIT_PROVISIONER_NAME:
        print("Incorrect name for first provisioner")
        return False

    return True


with open(CONFIGPATH, "r") as f:
    config = json.loads(f.read())

config = cfg_patch_db(config)
config = cfg_patch_remote_admin(config)

# patch out original listen addresses
orig_addr = config["address"]
orig_insecure_addr = config["insecureAddress"]

config["address"] = "127.0.0.1:5443"
config["insecureAddress"] = ""

# write patched config
with open(CONFIGPATH, "w") as f:
    f.write(json.dumps(config, indent=4))

# temporarily launch step-ca
# to force migration of the initial provisioners from ca.json to the database
proc_ca = subprocess.Popen(
    ["/usr/local/bin/step-ca", "--password-file", "/home/step/secrets/password", "/home/step/config/ca.json"])

try:
    for _ in range(30):
        try:
            res = httpx.get("https://127.0.0.1:5443/provisioners", verify=False, timeout=2.0)
            res.raise_for_status()

            out = res.json()

            if validate_provisioners(out):
                break
            else:
                print("Failed to validate provisioners.")
        except httpx.HTTPError as e:
            print("Failed to check provisioners: " + str(e))

        time.sleep(1.0)
    else:
        raise RuntimeError("Failed to")
finally:
    # ensure Step CA is shut down
    proc_ca.kill()

outs, errs = proc_ca.communicate()

if proc_ca.returncode != -9:
    raise RuntimeError("Step CA unexpected exit code: " + str(proc_ca.returncode))

# restore original listen addresses
config["address"] = orig_addr
config["insecureAddress"] = orig_insecure_addr

# remove provisioners from config
# they are already migrated into PostgreSQL db
config["authority"]["provisioners"] = []

# write patched config
with open(CONFIGPATH, "w") as f:
    f.write(json.dumps(config, indent=4))

print("[!] Finished patch_cfg_init.py")
