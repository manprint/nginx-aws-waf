FROM owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211
USER root
# nginx temp dirs live directly under /tmp (tmpfs at runtime); the master runs as root, workers as nginx.
RUN mkdir -p /etc/waf/runtime /etc/waf/lists /etc/waf/certs /etc/waf/geoip /var/log/waf \
 && chown -R nginx:nginx /var/log/waf
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://127.0.0.1:8090/healthz || exit 1
ENTRYPOINT []
CMD ["nginx", "-g", "daemon off;", "-c", "/etc/waf/runtime/current/nginx/nginx.conf"]
