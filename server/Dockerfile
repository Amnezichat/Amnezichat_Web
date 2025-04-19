FROM debian:12

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    git \
    tor \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

RUN git clone https://github.com/umutcamliyurt/Amnezichat.git .

WORKDIR /app/server

RUN cargo build --release

EXPOSE 8080

RUN mkdir -p /var/lib/tor/hidden_service && \
    echo "HiddenServiceDir /var/lib/tor/hidden_service" >> /etc/tor/torrc && \
    echo "HiddenServicePort 80 127.0.0.1:8080" >> /etc/tor/torrc && \
    chown -R debian-tor:debian-tor /var/lib/tor/hidden_service && \
    chmod 700 /var/lib/tor/hidden_service

CMD service tor start && sleep 5 && cat /var/lib/tor/hidden_service/hostname && cargo run --release
