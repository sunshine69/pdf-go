# signsrv in a container. The binary is a single artifact: the web apps and the
# templates are embedded at build time, so there is nothing to copy at runtime.
#
# The image is not a deployment. The service speaks plain HTTP and a proxy in
# front of it holds the certificate. The default listener is loopback, but that
# is a default and not a restriction: the service binds whatever address you
# name, and a bind outside loopback only prints a warning saying TLS, a proxy,
# or network policy has to terminate encryption in front of it. Where the
# listener sits is the operator's infrastructure decision. See
# docs/DEPLOY-DOCKER.md.
#
#   docker build -t signsrv:v0.0.1 -f deploy/Dockerfile .
#   docker run --rm -v signsrv-data:/var/lib/signsrv \
#       -e KEYSTORE_PASS=... -e ADMIN_PASSWORD=... \
#       signsrv:v0.0.1 checkconfig
#
# State: the container writes to /var/lib/signsrv (the database, the document
# store, the keystore, the JWT key, the audit log, the mail outbox). Mount a
# volume there. The keystore passphrase and the admin password come from the
# environment, never from the image, and never from a file baked into it.

FROM golang:1.27-alpine AS build

WORKDIR /src

# The dependency graph first, so a code-only change reuses the module download
# layer. There is no vendor tree: the build pulls from the module cache and
# verifies the checksums in go.sum.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY web/ web/

# CGO is off: the SQLite driver is pure Go (modernc.org/sqlite), so the binary
# is static and the runtime image needs no libc.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w" -o /signsrv ./cmd/signsrv
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w" -o /signsrv-utils ./cmd/signsrv-utils

FROM alpine:3.21

# ca-certificates is for the timestamp authority. The signing path calls the TSA
# over HTTPS, and a container without the bundle cannot verify the certificate
# chain, so every signature would be made without a timestamp. sqlite is a
# convenience: a container without it cannot read the state volume.
RUN apk add --no-cache ca-certificates sqlite && adduser -D -H -u 10001 signsrv

COPY --from=build /signsrv /usr/bin/signsrv
COPY --from=build /signsrv-utils /usr/bin/signsrv-utils

# The state directory. It is owned by the service user, and the keystore is
# mode 0750: readable by the service, not by anything else in the image.
RUN mkdir -p /var/lib/signsrv/keystore /var/lib/signsrv/storage \
    /var/lib/signsrv/outbox /var/lib/signsrv/log /var/lib/signsrv/audit \
    && chown -R signsrv:signsrv /var/lib/signsrv \
    && chmod 0750 /var/lib/signsrv/keystore

USER signsrv
WORKDIR /var/lib/signsrv

EXPOSE 8080

VOLUME /var/lib/signsrv

# LISTEN is loopback by default: the common shape is a proxy in front
# with TLS terminated there. It is a default, not a ceiling — set it to
# 0.0.0.0:8080 to publish the port, or to a specific interface address, and the
# service binds it. It then prints, at every start, a warning that it serves
# plain HTTP and that encryption has to be terminated in front of it; it does
# not refuse the bind, because the surrounding network is not visible to the
# container and the decision is the operator's.
#
# TRUST_PROXY=1 is right when a proxy you control sets X-Forwarded-For:
# without it the rate limits bind to the socket peer, which is the proxy, and
# every visitor shares one bucket. It is wrong when clients reach the listener
# directly — including on a published bind with nothing in front — because then
# a client chooses the address the limits are keyed to.
#
# PUBLIC_URL is not defaulted here on purpose: it is the address the
# signing links are built from, so a guessed default would produce links that
# look real and go nowhere. checkconfig refuses a serve without it.
ENV LISTEN=127.0.0.1:8080 \
    DB=/var/lib/signsrv/signsrv.db \
    STORAGE_DIR=/var/lib/signsrv/storage \
    KEYSTORE_DIR=/var/lib/signsrv/keystore \
    OUTBOX_DIR=/var/lib/signsrv/outbox \
    LOG_PATH=/var/lib/signsrv/log/signsrv.jsonl \
    AUDIT_DIR=/var/lib/signsrv/audit \
    JWT_SECRET_FILE=/var/lib/signsrv/jwt.ed25519.key

ENTRYPOINT ["/usr/bin/signsrv"]
CMD ["serve"]
