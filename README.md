<div align="right">
  <a href="README.md">🇺🇸 English</a> |
  <a href="README_TR.md">🇹🇷 Türkçe</a>
</div>

# Amnezichat

<img src="banner.png" width="1200">

## Anti-forensic and secure messenger
<!-- DESCRIPTION -->
## Description:

Amnezichat offers a highly secure and privacy-focused messaging experience by ensuring that no logs are retained and all message data is stored exclusively in the server's RAM. This approach significantly enhances user privacy because RAM storage is inherently volatile data is automatically erased when the server is powered down or restarted, leaving no trace of already end-to-end encrypted past communications.

<!-- FEATURES -->
## Features:

- Client-side quantum-resistant E2E message encryption

- Forward and backward secrecy for one-to-one chats

- Group chat support using PSK (pre-shared-key)

- Server runs even on cheapest hardware

- Each message is stored encrypted in server's RAM and wiped after 24 hours

- All traffic is routed over Tor/I2P network by default

- Docker support

- Built in Rust

## Comparison chart with other messengers:

![comparison_chart](comparison_chart.png)

## Technical details:

- Defense against AI-guided Traffic Analysis (DAITA) by sending encrypted dummy data at random intervals and padding all messages to a fixed length except files

![packet_capture](packet_capture.png)

- [Amnezichat Protocol](PROTOCOL.md) for end-to-end encryption
- Stores identity keys in local storage encrypted with ChaCha20-Poly1305 and Argon2id KDF with an user specified password

### Amnezichat Protocol:
- EdDSA and Dilithium5 for authentication, ECDH and Kyber1024 for key exchange, encryption using ChaCha20-Poly1305

<!-- INSTALLATION -->
## Server setup:

    sudo apt update
    sudo apt install curl build-essential git
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    git clone https://github.com/umutcamliyurt/Amnezichat.git
    cd Amnezichat/server/
    cargo build --release
    cargo run --release

## Server setup with Docker:
    
    sudo apt update
    sudo apt install docker.io git
    git clone https://github.com/umutcamliyurt/Amnezichat.git
    cd Amnezichat/server/
    sudo docker build -t amnezichatserver:latest .
    sudo docker run -p 8080:8080 amnezichatserver:latest

## Client setup:

**For Web UI connect to http://localhost:8000**

    sudo apt update
    sudo apt install curl build-essential git tor
    sudo systemctl enable --now tor.service
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    git clone https://github.com/umutcamliyurt/Amnezichat.git
    cd Amnezichat/client/
    cargo build --release
    cargo run --release

## Client setup with Docker:

    sudo apt update
    sudo apt install docker.io git
    git clone https://github.com/umutcamliyurt/Amnezichat.git
    cd Amnezichat/client/
    sudo docker build -t amnezichat:latest .
    sudo docker run -p 8000:8000 amnezichat:latest

## Requirements:

- [Rust](https://www.rust-lang.org), [Tor](https://gitlab.torproject.org/tpo/core/tor), [I2P](https://i2pd.website/)

<!-- SCREENSHOT -->
## Screenshot:

![Screenshot](screenshot.png)

<!-- LICENSE -->
## License

Distributed under the GPLv3 License. See `LICENSE` for more information.

## [Join us](https://matrix.to/#/#amnezichat_official:matrix.org) on Matrix!

## Donate to support development of this project!

**Monero(XMR):** 88a68f2oEPdiHiPTmCc3ap5CmXsPc33kXJoWVCZMPTgWFoAhhuicJLufdF1zcbaXhrL3sXaXcyjaTaTtcG1CskB4Jc9yyLV

**Bitcoin(BTC):** bc1qn42pv68l6erl7vsh3ay00z8j0qvg3jrg2fnqv9
