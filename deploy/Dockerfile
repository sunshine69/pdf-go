# signsrv in a container. The binary is a single artifact: the apps are
# embedded at build time, so there is nothing to copy at runtime.
#
# The image is not a deployment. TLS is terminated in front of the service,
# so the container listens on a loopback address inside the network namespace
# and a proxy in front of it holds the certificate. See deploy/Caddyfile.
#
#   docker build -t signsrv .
#   docker run --rm -v /var/lib/signsrv:/var/lib/signsrv signsrv checkconfig
#
# State: the container writes to /var/lib/signsrv (the database, the document
# store, the keystore, the JWT key). Mount it. The keystore passphrase and the
# admin password come from the environment, never from the image.

FROM golang:1.27-alpine AS build

WORKDIR /src

# The vendor tree is committed, so the build is reproducible and does not
# reach the network. -mod=vendor is explicit: it is the mode every test in
# this project runs in.
COPY go.mod go.sum vendor/ ./
RUN go mod verify

COPY cmd/ cmd/
COPY internal/ internal/
COPY web/ web/

# CGO is off: the SQLite driver is pure Go (modernc.org/sqlite), so the binary
# is static and the runtime image needs no libc.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath \
    -ldflags "-s -w" -o /signsrv ./cmd/signsrv

FROM alpine:3.21

# ca-certificates is for the timestamp authority. The signing path calls the
# TSA over HTTPS, and a container without the bundle cannot verify the
# certificate chain, so every signature would be made without a timestamp.
RUN apk add --no-cache ca-certificates sqlite && adduser -D -H -u 10001 signsrv

COPY --from=build /signsrv /usr/local/bin/signsrv

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

# SIGNSRV_LISTEN is loopback by default, which is the shape the deployment
# expects: a proxy in front, TLS terminated there. SIGNSRV_TRUST_PROXY=1 is
# required when the proxy sets X-Forwarded-For; without it the rate limits
# bind to the socket peer, which is the proxy.
ENV SIGNSRV_LISTEN=127.0.0.1:8080 \
    SIGNSRV_DB=/var/lib/signsrv/signsrv.db \
    SIGNSRV_STORAGE_DIR=/var/lib/signsrv/storage \
    SIGNSRV_KEYSTORE_DIR=/var/lib/signsrv/keystore \
    SIGNSRV_OUTBOX_DIR=/var/lib/signsrv/outbox \
    SIGNSRV_LOG_PATH=/var/lib/signsrv/log/signsrv.jsonl \
    SIGNSRV_AUDIT_DIR=/var/lib/signsrv/audit \
    SIGNSRV_JWT_SECRET_FILE=/var/lib/signsrv/jwt.ed25519.key

ENTRYPOINT ["/usr/local/bin/signsrv"]
CMD ["serve"]
