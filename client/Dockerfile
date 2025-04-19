FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && \
    apt-get install -y \
        curl \
        build-essential \
        git \
        tor && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN git clone https://github.com/umutcamliyurt/Amnezichat.git /opt/Amnezichat

WORKDIR /opt/Amnezichat/client
RUN cargo build --release

EXPOSE 8000

CMD tor & cargo run --release
