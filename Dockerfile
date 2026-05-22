# Build stage
FROM rust:1.81-slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev musl-tools
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

# Final stage
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/pellet /pellet
COPY --from=builder /app/pellet.toml /etc/pellet/pellet.toml
USER 1000:1000
ENTRYPOINT ["/pellet", "--config", "/etc/pellet/pellet.toml"]
