FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ARG OPHIS_COMMIT=8873359a0913d94e56a129a6b601dfc18a6574ab

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cc65=2.19-1 \
        git \
        make \
        python3 \
        python3-pil \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/michaelcmartin/Ophis.git /opt/ophis \
    && git -C /opt/ophis checkout --detach "${OPHIS_COMMIT}" \
    && python3 -m pip install \
        --break-system-packages \
        --no-cache-dir \
        --no-deps \
        /opt/ophis \
    && test "$(git -C /opt/ophis rev-parse HEAD)" = "${OPHIS_COMMIT}"

RUN test "$(dpkg-query -W -f='${Version}' cc65)" = "2.19-1" \
    && ca65 --version \
    && ld65 --version \
    && ophis --version

WORKDIR /work
