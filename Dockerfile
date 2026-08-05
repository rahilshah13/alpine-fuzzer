FROM alpine:latest

RUN apk update && apk add --no-cache \
    build-base \
    git \
    libedit-dev \
    openssl-dev \
    libffi-dev

WORKDIR /app
RUN git clone https://github.com/trealla-prolog/trealla.git /tmp/trealla && \
    cd /tmp/trealla && \
    make NOTHREADS=1 && \
    cp tpl /usr/local/bin/tpl && \
    rm -rf /tmp/trealla

COPY fuzz_runner.c fuzzer.pl alpine_libs.pl ./
RUN gcc -O2 -fno-stack-protector -D_GNU_SOURCE fuzz_runner.c -o fuzz_runner -ldl
CMD ["tpl", "fuzzer.pl"]