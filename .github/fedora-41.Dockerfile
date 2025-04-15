FROM fedora:41

RUN dnf --disablerepo=* --enablerepo=fedora,updates --nodocs --setopt=install_weak_deps=False -y install \
    autoconf \
    automake \
    gawk \
    bpftool \
    bison \
    clang-tools-extra \
    cmake \
    doxygen \
    flex \
    gcc \
    gcc-c++ \
    git-core \
    google-benchmark-devel \
    iproute \
    iputils \
    jq \
    lcov \
    libbpf-devel \
    libcmocka-devel \
    libgit2-devel \
    libnl3-devel \
    libtool \
    python3-breathe \
    python3-dateutil \
    python3-furo \
    python3-GitPython \
    python3-linuxdoc \
    python3-scapy \
    python3-sphinx && \
    dnf clean all -y
