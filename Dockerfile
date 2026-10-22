# engine-api and engine-cli in one small image. Built natively for linux/amd64 and
# linux/arm64 by .github/workflows/containers.yml (the base images are multi-architecture).
# Run it with DATABASE_URL set (roles and grants: docs/DATABASE-PRIVILEGES.md); with no
# configuration it refuses to start and says why.
FROM rust:1.96-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --locked --release -p engine-api -p engine-cli

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home dynodoc
COPY --from=build /app/target/release/engine-api /usr/local/bin/engine-api
COPY --from=build /app/target/release/engine-cli /usr/local/bin/engine-cli
COPY LICENSE NOTICE /usr/share/doc/dynodoc-engine/
USER dynodoc
EXPOSE 8080
CMD ["engine-api"]
