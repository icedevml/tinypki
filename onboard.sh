#!/bin/bash

set -e

echo "[!] Downloading CA roots"
export CA_URL=https://localhost:9000
curl -k -o ca_roots.pem "${CA_URL}/roots.pem"

export CA_FINGERPRINT=$(cat ca_roots.pem | openssl x509 -fingerprint -sha256 -noout -in /dev/stdin | head -n1 | cut -d= -f2 | tr -d ':')
echo "[!] Bootstraping Step CLI with CA fingerprint: ${CA_FINGERPRINT}"
step ca bootstrap --ca-url "${CA_URL}" --fingerprint "${CA_FINGERPRINT}"

echo "[!] Requesting a superadmin certificate through default JWK admin provisioner"
step ca certificate step step.crt step.key --provisioner=admin --password-file=env/stepca_password
echo "[!] Exporting certificate and key to PKCS#12 container"
openssl pkcs12 -export -out step.p12 -inkey step.key -in step.crt -password pass:admin

echo ""
echo "--------------------------------------------------------------------------"
echo "[#] Exported superadmin certificate/key"
echo "[#] -> File name: step.p12"
echo "[#] -> Password: admin"
echo "--------------------------------------------------------------------------"
echo ""

echo "[!] Adding a new provisioner 'tinypki'"
TINYPKI_PWD=$(openssl rand -base64 24)
echo -n "$TINYPKI_PWD" > /tmp/tinypki_provisioner_password
step ca provisioner add tinypki --create --type=JWK --admin-cert=step.crt --admin-key=step.key --password-file=/tmp/tinypki_provisioner_password
echo "[!] Setting max cert duration to ~2 years"
step ca provisioner update tinypki --admin-cert=step.crt --admin-key=step.key --x509-max-dur=17760h

echo ""
echo "--------------------------------------------------------------------------"
echo "[#] Created new JWK provisioner"
echo "[#] -> Provisioner name: tinypki"
echo "[#] -> Provisioner password: $TINYPKI_PWD"
echo "[#] You will need to provide these details in the TinyPKI dashboard 'Provisioners' -> 'Add provisioner' section"
echo "--------------------------------------------------------------------------"
echo ""

echo "[!] All done!"
