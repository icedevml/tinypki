FROM caddy:2.10.2-alpine

RUN apk add --no-cache python3 py3-httpx
COPY entrypoint.sh entrypoint.py /

WORKDIR /srv

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
