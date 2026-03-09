FROM golang:1.26.0-alpine3.23 AS tool-build

RUN apk add --no-cache git && \
    mkdir /app && \
    cd /app && \
    git clone --depth 1 --revision 95e687879ea65e351f02b7644aeec340cf730e4b https://github.com/smallstep/certificates.git

RUN cd /app/certificates && \
    go build -o badger-migration ./scripts/badger-migration/

FROM smallstep/step-ca:0.29.0

USER root

RUN apk add --no-cache python3 py3-httpx postgresql-client
COPY --from=tool-build /app/certificates/badger-migration /usr/local/bin/badger-migration
RUN chmod +x /usr/local/bin/badger-migration

USER step
COPY wrap_entrypoint.sh patch_cfg_init.py patch_cfg_run.py common_boolutil.py common_cfg.py /extra/

ENTRYPOINT ["/bin/bash", "/extra/wrap_entrypoint.sh"]
CMD ["/usr/local/bin/step-ca", "--password-file", "/home/step/secrets/password", "/home/step/config/ca.json"]
