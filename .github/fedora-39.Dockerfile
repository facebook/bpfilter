FROM fedora:39

RUN dnf --disablerepo=* --enablerepo=fedora,updates --nodocs --setopt install_weak_deps=False -y install \
    bison \
    clang-tools-extra \
    cmake \
    flex \
    libcmocka-devel \
    doxygen \
    gcc-c++ \
    git \
    lcov \
    libasan \
    libbpf-devel \
    libnl3-devel \
    libubsan \
    python3-breathe \
    python3-furo \
    python3-linuxdoc \
    python3-scapy \
    python3-sphinx \
    pkgconf \
    google-benchmark-devel \
    libgit2-devel && \
    dnf clean all -y
