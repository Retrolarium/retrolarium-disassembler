FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc-m68k-linux-gnu binutils-m68k-linux-gnu binutils-z80 python3-pygame && rm -rf /var/lib/apt/lists/*
