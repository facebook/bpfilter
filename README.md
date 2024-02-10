BPF-based packet filtering framework
---

`bpfilter` is a daemon and shared library aiming to translate packet filtering rules into BPF programs.

## Quick start

To quickly get `bpfilter` up and running on Fedora (38+):

```shell
# Install dependencies
sudo dnf install \
    clang-tools-extra \
    cmake \
    libcmocka-devel \
    doxygen \
    lcov \
    libasan \
    libbpf-devel \
    libubsan \
    python3-breathe \
    python3-furo \
    python3-sphinx \
    pkgconf

# Build bpfilter
cmake -S $BPFILTER_SOURCES -B $BPFILTER_BUILD
make -C $BPFILTER_BUILD
make -C $BPFILTER_BUILD test

# Start bpfilter's daemon
sudo $BPFILTER_BUILD/src/bpfilter
```

The [official documentation](https://facebook.github.io/bpfilter/index.html) contains more details about building the project for Fedora and Ubuntu, as well as building front-ends (e.g. `iptables`) to use with `bpfilter`, and an API reference.

## License

bpfilter is GPLv2 licensed, as found in the COPYING file.

`bpfilter` was originally developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).
