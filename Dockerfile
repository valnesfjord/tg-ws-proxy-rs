FROM rust:1-alpine AS builder

WORKDIR /app

RUN apk add --no-cache ca-certificates cmake g++ make musl-dev perl pkgconf

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM scratch AS runtime

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/target/release/tg-ws-proxy /usr/local/bin/tg-ws-proxy

COPY <<EOF /etc/passwd
tgws:x:1000:1000:tg-ws-proxy user:/nonexistent:/sbin/nologin
EOF
COPY <<EOF /etc/group
tgws:x:1000:
EOF

USER 1000:1000
EXPOSE 1443

ENTRYPOINT ["tg-ws-proxy"]
