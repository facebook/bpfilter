FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y \
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
        libnl3-dev \
        libubsan1 \
        pkgconf \
        python3-breathe \
        furo \
        python3-pip \
        python3-sphinx \
        libbenchmark-dev \
        libgit2-dev

RUN pip3 install linuxdoc