import itertools
import os
import time

import httpx

tmpl = """
{
    acme_ca https://ca:9000/acme/acme/directory
    email admin@example.com
    acme_ca_root @@ACME_CA_ROOT@@
}

@@HOSTNAME@@ {
    reverse_proxy http://webapp:8080 {
        header_up X-Proxy-Auth @@PROXY_AUTH@@
        header_up X-Client-Cert {tls_client_certificate_der_base64}
    }
    tls {
        client_auth {
            mode verify_if_given
            trust_pool file {
                pem_file @@TRUST_POOL_FILES@@
            }
        }
    }
}
"""

TINYPKI_HOSTNAME = os.environ["TINYPKI_HOSTNAME"]
PROXY_AUTH_TOKEN = os.environ.get("PROXY_AUTH_TOKEN")

if not PROXY_AUTH_TOKEN or len(PROXY_AUTH_TOKEN) < 16:
    raise RuntimeError("PROXY_AUTH_TOKEN must be at least 16 characters long - use a secure random.")


def load_certs(path: str, prefix: str):
    res = httpx.get("https://ca:9000" + path, verify=False)
    res.raise_for_status()

    i = 0

    for cert_pem in res.json()["crts"]:
        fn = prefix + str(i) + ".pem"
        fp = os.path.join("/etc/caddy/certs", fn)

        with open(fp, "w") as f:
            f.write(cert_pem)

        yield fp


while True:
    print("[!] Waiting for Step CA to become healthy...")

    try:
        res = httpx.get("https://ca:9000/health", verify=False, timeout=2)
        res.raise_for_status()

        if res.json().get("status") == "ok":
            break
    except httpx.HTTPError as e:
        print(f"HTTP Exception for {e.request.url} - {e}")

    time.sleep(1.0)

if not os.path.exists("/etc/caddy/certs"):
    os.mkdir(os.path.join("/etc/caddy", "certs"))

roots = list(load_certs("/roots", "root"))
intermediates = list(load_certs("/intermediates", "intermediate"))

acme_ca_root = ' '.join(roots)
trust_pool_files = ' '.join(itertools.chain(roots, intermediates))

with open("/etc/caddy/Caddyfile", "w") as f:
    tmpl = tmpl.strip()
    tmpl = tmpl.replace("@@HOSTNAME@@", TINYPKI_HOSTNAME)
    tmpl = tmpl.replace("@@PROXY_AUTH@@", PROXY_AUTH_TOKEN)
    tmpl = tmpl.replace("@@ACME_CA_ROOT@@", acme_ca_root)
    tmpl = tmpl.replace("@@TRUST_POOL_FILES@@", trust_pool_files)
    f.write(tmpl)

print("[!] Entry script done!")
