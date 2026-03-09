# Local development

The simplest way is to only run `ca-services.yml` via Docker, and then setup this project locally,
making sure that all variables in `env/` are in sync and with proper URLs specified everywhere.

If Step CA keeps on throwing "401 Unauthorized" you may need to adjust `DOCKER_STEPCA_INIT_DNS_NAMES` to cover
for the exact hostname/IP that TinyPKI is using to connect to Step CA.
