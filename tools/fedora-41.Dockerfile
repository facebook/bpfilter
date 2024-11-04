FROM fedora:41

RUN dnf --disablerepo=* --enablerepo=fedora,updates --setopt=install_weak_deps=False -y install \
    bison \
    bpftool \
    clang \
    clang-tools-extra \
    cmake \
    flex \
    libcmocka-devel \
    doxygen \
    git \
    jq \
    lcov \
    libasan \
    libbpf-devel \
    libnl3-devel \
    libubsan \
    python3-breathe \
    python3-furo \
    python3-linuxdoc \
    python3-sphinx \
    pkgconf \
    google-benchmark-devel \
    libgit2-devel
