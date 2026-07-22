FROM fedora:rawhide

# Rawhide does not have an `updates` repo (it is the rolling development
# branch; all updates land directly in `fedora`).
# Rawhide only ships versioned libgit2 packages, hence libgit2_1.9-devel
# instead of libgit2-devel.
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
    libgit2_1.9-devel \
    libpfm-devel \
    libtool \
    pipx \
    procps-ng \
    python3-breathe \
    python3-dateutil \
    python3-furo \
    python3-GitPython \
    python3-pip \
    python3-scapy \
    python3-sphinx \
    sed \
    xxd && \
    dnf clean all -y

# python3-linuxdoc is not installable until it is rebuilt against rawhide's
# current Python, install it from PyPI instead.
RUN pip install --break-system-packages linuxdoc && \
    pipx install --global ast-grep-cli && \
    ast-grep --version
