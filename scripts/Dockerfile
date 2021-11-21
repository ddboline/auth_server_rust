FROM rust:alpine3.14 as buildstage

RUN apk add musl-dev && mkdir -p /build/auth_server_rust

ADD Cargo.toml /build/auth_server_rust/
COPY src /build/auth_server_rust/src
COPY auth_server_admin /build/auth_server_rust/auth_server_admin
COPY auth_server_ext /build/auth_server_rust/auth_server_ext
COPY auth_server_http /build/auth_server_rust/auth_server_http
COPY auth_server_lib /build/auth_server_rust/auth_server_lib
COPY authorized_users /build/auth_server_rust/authorized_users
COPY migrations /build/auth_server_rust/migrations
COPY templates /build/auth_server_rust/templates

RUN mkdir -p /auth_server_rust && \
    cd /build/auth_server_rust && \
    cargo install --path=. --root=/auth_server_rust

FROM alpine:3.14

COPY --from=buildstage /auth_server_rust/bin/* /usr/bin/

STOPSIGNAL SIGTERM

EXPOSE 3097

CMD ["/usr/bin/auth-server-rust"]

