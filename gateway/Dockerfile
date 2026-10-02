FROM nginxinc/nginx-unprivileged:stable-alpine@sha256:ed04ec1ff34502c339ee5c3ae3f855442398edc1d05591e2b98981dcbbd20b1e
USER 0
# Fixed PCRE2 release for CVE-2026-103111, detected by the release scan.
RUN apk add --no-cache --upgrade pcre2=10.49-r0
USER 101
ARG SOURCE_REVISION=local
LABEL org.opencontainers.image.title="TrustPass Gateway" \
      org.opencontainers.image.source="https://github.com/jorgefprietol/trustpass-platform" \
      org.opencontainers.image.revision=$SOURCE_REVISION
COPY gateway/nginx.conf /etc/nginx/nginx.conf
COPY web /usr/share/nginx/html
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1
