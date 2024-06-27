FROM ubuntu:20.04

RUN apt update && apt -y install \
    build-essential \
    clang \
    curl \
    python3-dev

ENV RUSTUP_HOME=/opt/rust
ENV CARGO_HOME=/opt/rust
ENV PATH=$PATH:/opt/rust/bin

COPY scripts/install_build_tools.sh .
RUN bash install_build_tools.sh
