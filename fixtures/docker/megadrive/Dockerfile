FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS build

ARG CLOWNASSEMBLER_COMMIT=0842de46bfb2db44fbd9e1e3d5cc7e366fb965e5
ARG MDTOOLS_COMMIT=e1d84036e56c896c6124163cea37bbbd8941813a

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      bison build-essential ca-certificates flex git libpng-dev \
 && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/Clownacy/clownassembler.git /src/clownassembler \
 && git -C /src/clownassembler checkout --detach "${CLOWNASSEMBLER_COMMIT}" \
 && git -C /src/clownassembler submodule update --init clowncommon \
 && make -C /src/clownassembler assemblers

RUN git clone https://github.com/sikthehedgehog/mdtools.git /src/mdtools \
 && git -C /src/mdtools checkout --detach "${MDTOOLS_COMMIT}" \
 && make -C /src/mdtools/mdtiler/tool \
 && make -C /src/mdtools/slz/tool \
 && make -C /src/mdtools/uftc/tool \
 && make -C /src/mdtools/tfi2eif/tool \
 && make -C /src/mdtools/pcm2ewf/tool \
 && make -C /src/mdtools/romfix

FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update \
 && apt-get install --yes --no-install-recommends libpng16-16 php-cli \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/clownassembler/clownassembler_asm68k /usr/local/bin/asm68k
COPY --from=build /src/mdtools/mdtiler/tool/mdtiler /usr/local/bin/mdtiler
COPY --from=build /src/mdtools/slz/tool/slz /usr/local/bin/slz
COPY --from=build /src/mdtools/uftc/tool/uftc /usr/local/bin/uftc
COPY --from=build /src/mdtools/tfi2eif/tool/tfi2eif /usr/local/bin/tfi2eif
COPY --from=build /src/mdtools/pcm2ewf/tool/pcm2ewf /usr/local/bin/pcm2ewf
COPY --from=build /src/mdtools/romfix/romfix /usr/local/bin/romfix

WORKDIR /work
