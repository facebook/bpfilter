BPF-based packet filtering framework
---

`bpfilter` is a BPF-based packet filtering framework. `bpfilter` has two major components: a daemon running on the host and translating filtering rules into BPF programs, and a lightweight library to communicate with the daemon.

`bpfilter` is a solution to translate filtering rules, not to create them. However, this repository contains a set of patches to apply to `iptables` and `nftables` to use them with `bpfilter`. See the [documentation](https://bpfilter.io) for more details.

## Quick start

To quickly get `bpfilter` up and running on Fedora 40:

```shell
# Install dependencies
sudo dnf install -y \
    bison \
    bpftool \
    clang \
    clang-tools-extra \
    cmake \
    flex \
    libcmocka-devel \
    doxygen \
    git \
    lcov \
    libasan \
    libbpf-devel \
    libnl3-devel \
    libubsan \
    python3-breathe \
    python3-furo \
    python3-linuxdoc \
    python3-sphinx \
    pkgconf

# Build bpfilter
cmake -S $SOURCES_DIR -B $BUILD_DIR
make -C $BUILD_DIR
make -C $BUILD_DIR test

# Build a custom version of nftables and iptables to use with bpfilter
make -C $BUILD_DIR nftables iptables

# Start bpfilter's daemon
sudo $BUILD_DIR/src/bpfilter

# Run the custom version of nftables
sudo $BUILD_DIR/tools/install/sbin/nft --bpf ...

# Run the custom version of iptables
sudo $BUILD_DIR/tools/install/sbin/iptables --bpf ...
```

## License

bpfilter is GPLv2 licensed, as found in the COPYING file.

`bpfilter` was originally developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).
