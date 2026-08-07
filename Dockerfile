# Stargate — multi-stage build (Rust, distroless runtime)
FROM rust:1.97-alpine AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/target/release/stargate /stargate
EXPOSE 3200
ENTRYPOINT ["/stargate"]
