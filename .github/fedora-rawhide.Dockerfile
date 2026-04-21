FROM fedora:rawhide

# Rawhide does not have an `updates` repo (it is the rolling development
# branch; all updates land directly in `fedora`).
RUN dnf --disablerepo=* --enablerepo=fedora --nodocs --setopt=install_weak_deps=False -y install \
    autoconf \
    automake \
    gawk \
    bpftool \
    bison \
    clang \
    clang-tools-extra \
    cmake \
    compiler-rt \
    doxygen \
    flex \
    gcc \
    gcc-c++ \
    git-core \
    google-benchmark-devel \
    include-what-you-use \
    iproute \
    iputils \
    jq \
    lcov \
    libbpf-devel \
    libcmocka-devel \
    libgit2-devel \
    libpfm-devel \
    libtool \
    pipx \
    procps-ng \
    python3-breathe \
    python3-dateutil \
    python3-furo \
    python3-GitPython \
    python3-linuxdoc \
    python3-scapy \
    python3-sphinx \
    sed \
    xxd && \
    dnf clean all -y

RUN pipx install --global ast-grep-cli && \
    ast-grep --version
