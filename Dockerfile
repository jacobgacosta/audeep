# AuDeep — Dockerfile musl estático (offline, 7MB)
# Build: docker build -t audeep:latest .
# Run: docker run --rm --network host -v %cd%:/out audeep:latest
#      docker run --rm -p 8766:8766 audeep:latest --serve 0.0.0.0:8766

FROM rust:1.98-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && rm -rf /var/lib/apt/lists/*
# zig 0.16 para musl sin glibc
RUN curl -L https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz -o /tmp/zig.tar.xz \
 && tar -xf /tmp/zig.tar.xz -C /tmp && mv /tmp/zig-x86_64-linux-0.16.0 /opt/zig && ln -s /opt/zig/zig /usr/local/bin/zig
RUN cargo install cargo-zigbuild --locked
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
COPY xtask ./xtask
COPY .cargo ./.cargo
RUN cargo zigbuild --target x86_64-unknown-linux-musl --release

FROM scratch AS export
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/audeep /audeep
ENTRYPOINT ["/audeep"]

FROM gcr.io/distroless/static:nonroot AS runtime
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/audeep /usr/local/bin/audeep
EXPOSE 8766
ENTRYPOINT ["audeep"]
CMD ["--help"]
