# Use official Alpine Linux image
FROM alpine:latest

# Install build essentials, git, and development headers
RUN apk update && apk add --no-cache \
    build-base \
    git \
    readline-dev \
    openssl-dev \
    libffi-dev

# Set working directory
WORKDIR /app

# Clone and build Trealla Prolog from source
RUN git clone https://github.com/trealla-prolog/trealla.git /tmp/trealla && \
    cd /tmp/trealla && \
    make && \
    cp tpl /usr/local/bin/tpl && \
    rm -rf /tmp/trealla

# Copy the C harness and Prolog orchestrator into the container
COPY fuzz_runner.c fuzz_rest.c* fuzz_runner.c fuzzer.pl ./

# If you copy them individually, ensure fuzz_runner.c and fuzzer.pl are present.
# Compile the C isolation harness
RUN gcc -O2 fuzz_runner.c -o fuzz_runner -ldl

# Default command to run the fuzzer and generate results
CMD ["tpl", "fuzzer.pl"]
