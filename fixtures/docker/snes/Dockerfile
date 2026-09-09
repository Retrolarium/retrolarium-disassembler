FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS pcx2snes-build

ARG PCX2SNES_COMMIT=defc63ebf0f45a055cf603d31d1ec07e58d194c1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      build-essential ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/bazz1tv/pcx2snes.git /src/pcx2snes \
 && git -C /src/pcx2snes checkout --detach "${PCX2SNES_COMMIT}" \
 && make -C /src/pcx2snes

FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      build-essential cc65=2.19-1 imagemagick make python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --break-system-packages --no-cache-dir \
      six==1.17.0 tmx==1.10

COPY --from=pcx2snes-build /src/pcx2snes/pcx2snes /usr/local/bin/pcx2snes
COPY ucon64.py /usr/local/bin/ucon64
RUN chmod 0755 /usr/local/bin/ucon64

WORKDIR /work
