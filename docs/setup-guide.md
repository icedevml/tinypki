# Setup Guide

## Prerequisites

1. Install [Docker Engine](https://docs.docker.com/engine/install/)
2. Install [Step CLI](https://github.com/smallstep/cli/releases)

## Onboarding the first client certificate

After the CA is spun up, you need to configure the Step CLI to work accordingly with your new CA, and to use it in order
to obtain the first client certificate. Using that certificate you will be then able to authenticate to the TinyPKI dashboard.

Download the root CA certificate:
```
export CA_URL=https://localhost:9000
curl -k -o ca_roots.pem "${CA_URL}/roots.pem"
```

Bootstrap your Step CLI to work with the CA:
```
export CA_FINGERPRINT=$(cat ca_roots.pem | openssl x509 -fingerprint -sha256 -noout -in /dev/stdin | head -n1 | cut -d= -f2 | tr -d ':')
step ca bootstrap --ca-url "${CA_URL}" --fingerprint ${CA_FINGERPRINT}
```

> [!NOTE]
> The password to decrypt the JWK provisioner key is in `env/stepca_password`.

Issue a certificate for "CN=step" using the default JWK provisioner:
```
step ca certificate step step.crt step.key
```

> [!CAUTION]
> By default, all certificates with `CN=step` have a superadmin privilege in the Remote Provisioner Management feature.
> Make sure to safeguard the certificate accordingly, as it basically advocates for the entire CA's security.

Bundle your client certificate&key together into PKCS#12 container:
```
openssl pkcs12 -export -out step.p12 -inkey step.key -in step.crt
```

Finally:
1. Import `ca_roots.pem` as a trusted root CA in your system/browser.
2. Import `step.p12` as a client certificate/key in your system/browser.

> [!TIP]
> Your may need to restart the browser before your new certificates are correctly recognized.

#0## Open TinyPKI dashboard

1. Execute the following command to bind `tinypki.home` domain to localhost:
   ```
   echo "127.0.0.1 tinypki.home" >> /etc/hosts
   ```
2. Visit `https://tinypki.home:9443` and select your client certificate.

## Create JWK provisioner for TinyPKI

1. By default, TinyPKI only has the ability to peek into Step CA's database, although it does not hold any credentials
   that would allow it to request or revoke a certificate.
2. Create additional JWK provisioner called `tinypki`. The command is authenticated with your superadmin's client certificate (`step.crt`):
   ```
   step ca provisioner add tinypki --create --type=JWK --admin-cert=step.crt --admin-key=step.key
   ```
   Set a long secure password when creating the new provisioner. You will need to provide that password in the further step.
3. In the TinyPKI web dashboard, navigate to the "Provisioners" tab, click "Add provisioner". Enter
   the provisioner name `tinypki` and the password that you've just set in the previous step.
4. TinyPKI will now record these credentials in its database (with at-rest encryption), so now it will be able to internally
   request Step CA to perform certain operations. That enables the usage of TinyPKI features like "invitations" and certificate revocation.

## Adjust JWK provisioner's configuration

As per the defaults applied by Step CA, our `tinypki` JWK provisioner can issue certificates with the validity up to 24 hours only.

**Reconfiguration of the `tinypki` provisioner to allow issuance with validity up to 17760 hours (~2 years).**
```bash
step ca provisioner update tinypki --admin-cert=step.crt --admin-key=step.key --x509-max-dur=17760h
```

**Applying a custom template to the `tinypki` provisioner, so that the issued certificates will contain `O=TinyPKI Example` in their subject,
and will specify that the CRL is available at `https://ca.internal/1.0/crl`.**
```bash
cat > cert.tpl <<EOF
{
	"subject": {
		"organization": "TinyPKI Example",
		"commonName": {{ toJson .Subject.CommonName }}
	},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"],
	"crlDistributionPoints": ["https://ca.internal/1.0/crl"]
}
EOF

step ca provisioner update tinypki --admin-cert=step.crt --admin-key=step.key --x509-template=cert.tpl
```

Note that CRL endpoints are enabled in the default configuration through environment variables (`example-env/stepca.env`).

## Further Step CA configuration

With this project, Step CA ships with the remote provisioner management feature enabled by default.
By default, any certificate with `CN=step` has a superadmin privilege in Remote Provisioner Management.

Using the Remote Provisioner Management you will be able to configure new provisioners with the Step CA,
to modify the configuration of existing provisioners such as certificate templates, max certificate lifespans and other policies.

**Read more:** [Configuring step-ca Provisioners: Remote Provisioner Management](https://smallstep.com/docs/step-ca/provisioners/#use-remote-provisioner-management).

> [!NOTE]
> Note that the section "Unattended remove provisioner management" mentions obtaining an administrator certificate, which we just already did within this README as `step.crt` and `step.key`.
The section is mentioned for reference to make it easier to cross-connect the knowledge.

## Using TinyPKI with an external reverse proxy

By default, TinyPKI is covered behind a Caddy reverse proxy that handles the TLS Client Certificate authentication. You are welcome to drop that layer off
if you need and use your own external reverse proxy behind TinyPKI.

This is an example how external nginx configuration would look like:
```
    server {
        listen 443 ssl;
        server_name proxy.example.com;

        ssl_certificate         /etc/nginx/ssl/server.crt;
        ssl_certificate_key     /etc/nginx/ssl/server.key;
        ssl_client_certificate  /etc/nginx/ssl/client_chain.crt;
        ssl_verify_client       optional;

        location / {
            if ($ssl_client_verify ~* "^FAILED") {
                return 403 "Failed to verify client certificate.";
            }

            proxy_pass http://tinypki-container:8080;

            proxy_set_header Host                  $host;
            proxy_set_header X-Real-IP             $remote_addr;
            proxy_set_header X-Forwarded-For       $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto     $scheme;

            proxy_set_header X-Proxy-Auth          "<<PROXY_AUTH_TOKEN>>";
            proxy_set_header X-Client-Cert         $ssl_client_escaped_cert;
        }
    }
```
Note that `<<PROXY_AUTH_TOKEN>>` must be replaced with the value of the `PROXY_AUTH_TOKEN` environment variable
that is passed to the `tinypki` container. The `X-Proxy-Auth` is an additional security precaution.
