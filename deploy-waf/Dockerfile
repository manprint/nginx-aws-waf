# nginx + ModSecurity + catalogo AWS WAF in un'unica immagine "all-in-one" (nodo singolo, senza centrale).
# Build dalla root del repo:
#   docker build -f deploy-waf/Dockerfile -t ghcr.io/manprint/nginx-aws-waf/aio:latest .
# oppure: cd deploy-waf && docker compose build
# Immagine pubblicata (workflow .github/workflows/images.yml): ghcr.io/manprint/nginx-aws-waf/aio:latest | :vX.Y.Z | :<sha8>
#
# La config nginx/ModSecurity NON è nell'immagine: all'avvio (e a ogni modifica di /config)
# il container la renderizza con wafctl da node.yaml + sites/*.yaml (o dalle variabili d'ambiente).

ARG CRS_IMAGE=owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211
ARG GO_IMAGE=golang:1.27-alpine

# ---------- 1. wafctl (Go, statico) ----------
# gira sull'architettura della macchina di build e compila per quella di destinazione (multi-arch senza emulazione)
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS wafctl
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY wafctl/go.mod wafctl/go.sum ./
RUN go mod download
COPY wafctl/ ./
ARG WAF_VERSION=aio
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w -X nginxawswaf/wafctl/internal/version.Version=${WAF_VERSION}" \
      -o /out/wafctl ./cmd/wafctl

# ---------- 2. motore WAF ----------
FROM ${CRS_IMAGE}
USER root

# bash + python3: servono a scripts/fetch-ip-lists.sh (aggiornamento liste IP); tini: PID 1 che raccoglie i processi
RUN apk add --no-cache bash python3 tini

# SSL_CERT_FILE: l'immagine base lo punta al certificato dummy di nginx, e curl/OpenSSL lo usano come
# bundle CA → ogni download HTTPS (liste IP, GeoIP) fallirebbe con "error adding trust anchors".
ENV WAF_HOME=/opt/waf \
    WAF_CONFIG_DIR=/var/lib/waf/config \
    WAF_DATA_DIR=/srv/waf \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# prodotto: catalogo, file dati, pagine 403/500, profili, script liste, pipeline Vector del nodo
COPY --from=wafctl /out/wafctl /usr/local/bin/wafctl
COPY waf/catalog/ /opt/waf/waf/catalog/
COPY waf/data/    /opt/waf/waf/data/
COPY waf/static/  /opt/waf/waf/static/
COPY profiles/    /opt/waf/profiles/
COPY scripts/fetch-ip-lists.sh /opt/waf/scripts/fetch-ip-lists.sh
COPY deploy/vector/node.yaml   /opt/waf/deploy/vector/node.yaml

# liste IP di default (quelle presenti in data/ip-reputation al momento della build;
# con --build-arg FETCH_LISTS=1 vengono riscaricate durante la build)
COPY data/ip-reputation/ /opt/waf/lists-default/
ARG FETCH_LISTS=0
RUN rm -f /opt/waf/lists-default/custom-test.txt \
 && if [ "$FETCH_LISTS" = "1" ]; then \
      OUT=/opt/waf/lists-default bash /opt/waf/scripts/fetch-ip-lists.sh || echo "WARN: fetch liste fallito, uso quelle del repo"; \
      rm -f /opt/waf/lists-default/custom-test.txt; \
    fi

# Layout dati: $WAF_DATA_DIR punta ai percorsi che la config renderizzata usa dentro il container
RUN mkdir -p /etc/waf/runtime /etc/waf/lists /etc/waf/certs /etc/waf/geoip /var/log/waf \
             /srv/waf/state /srv/waf/raw /var/lib/waf /config \
 && ln -s /etc/waf/runtime /srv/waf/runtime \
 && ln -s /etc/waf/lists   /srv/waf/lists \
 && ln -s /etc/waf/certs   /srv/waf/certs \
 && ln -s /etc/waf/geoip   /srv/waf/geoip \
 && ln -s /var/log/waf     /srv/waf/logs \
 && chown -R nginx:nginx /var/log/waf

COPY deploy-waf/bin/ /usr/local/bin/
RUN chmod 0755 /usr/local/bin/waf /usr/local/bin/waf-entrypoint /usr/local/bin/waf-publish

EXPOSE 8080 8443
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s CMD wget -qO- http://127.0.0.1:8090/healthz || exit 1
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/waf-entrypoint"]
CMD ["nginx", "-g", "daemon off;", "-c", "/etc/waf/runtime/current/nginx/nginx.conf"]
