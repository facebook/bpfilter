FROM ubuntu:24.10

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        bison \
        linux-tools-common \
        clang \
        clang-tidy \
        clang-format \
        cmake \
        doxygen \
        flex \
        g++ \
        gcc \
        git \
        jq \
        lcov \
        libasan8 \
        libbpf-dev \
        libcmocka-dev \
        libnl-3-dev \
        libubsan1 \
        make \
        pkgconf \
        python3-breathe \
        python3-setuptools \
        python3-scapy \
        furo \
        python3-pip \
        python3-sphinx \
        libbenchmark-dev \
        libgit2-dev && \
        rm -rf /var/lib/apt/lists/*

RUN pip install --break-system-packages linuxdoc
