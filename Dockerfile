FROM rust:1.63.0 AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc AS runtime

WORKDIR /app
COPY --from=builder /app/target/release/dns-rebinder dns-rebinder

ENTRYPOINT ["./dns-rebinder"]