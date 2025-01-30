FROM fedora:41

RUN dnf --disablerepo=* --enablerepo=fedora,updates --nodocs --setopt install_weak_deps=False -y install \
    bison \
    bpftool \
    clang-tools-extra \
    cmake \
    flex \
    libcmocka-devel \
    doxygen \
    gcc-c++ \
    git \
    jq \
    lcov \
    libasan \
    libbpf-devel \
    libnl3-devel \
    libubsan \
    python3-breathe \
    python3-dateutil \
    python3-furo \
    python3-GitPython \
    python3-linuxdoc \
    python3-scapy \
    python3-sphinx \
    pkgconf \
    google-benchmark-devel \
    libgit2-devel && \
    dnf clean all -y
