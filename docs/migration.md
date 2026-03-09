# Migrate existing Step CA into TinyPKI setup

## Prerequisites

Before migrating your existing Step CA instance, make sure that you have at least one JWK provisioner configured,
and that you know the password for it.

If you are not sure, please [Add a JWK provisioner](https://smallstep.com/docs/step-ca/provisioners/#example) first.

## Preparing migration

1. Run `python3 makeenv.py`, edit the created environment files accordingly.
2. Pre-create the `step_data` volume (defined in `ca-services.yml`) and copy over all data from your existing Step CA installation.
3. Edit all absolute paths in `config/ca.json`, the root directory for the CA will be `/home/step`. For example, this config
   file will be mounted in `/home/step/config/ca.json`.
4. Set listen address to `:8443`.
5. Set allowed DNS hostnames to appropriate values.
6. Edit `TINYPKI_HOSTNAME` in `.env`.
7. Ensure that CA password is in `/home/step/secrets/password`.
8. You may drop the `db: { ... }` config key, appropriate entries will be added automatically.

## Migrating

Run `docker compose up --build`. The Badger database will automatically be migrated upon first launch.
