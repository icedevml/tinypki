# Security guidelines

1. If you wish to expose Step CA to the public internet directly, we recommend to hide it behind a reverse proxy and only allow whitelisted endpoints to pass through.
   For example, if you only need to expose ACME provisioner to the public internet, the reverse proxy shouldn't allow anything apart from `/acme/acme/` routes.
2. Make sure that none of your JWK provisioners is using a weak (<32 characters secure random) password. As per Step CA design, the provisioner configuration
   is remotely and publicly discoverable. In consequence, passwords for JWK provisioners may be offline brute-forced, so make sure to use really strong values everywhere.
3. Make sure that nobody could accidentally obtain a certificate that would qualify them as a superadmin or admin role with the Remote Provisioner Management feature.
   By default, any certificate with `CN=step` (or DNS SAN=`step`) is [treated as a superadmin](https://smallstep.com/docs/step-ca/provisioners/#authenticating-as-an-admin).

Also see [Production considerations when running a certificate authority server](https://smallstep.com/docs/step-ca/certificate-authority-server-production/) article.
