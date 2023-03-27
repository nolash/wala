FROM rust:1-slim-bullseye AS build

RUN apt-get update
RUN apt-get install -y build-essential clang llvm pkg-config nettle-dev

WORKDIR /build
COPY . /build

RUN cargo build --release --all-features --target x86_64-unknown-linux-gnu
RUN strip ./target/x86_64-unknown-linux-gnu/release/wala

FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUST_LOG=info

WORKDIR /service

COPY --from=build /build/target/x86_64-unknown-linux-gnu/release/wala .

EXPOSE 8000

CMD ["./wala"]
