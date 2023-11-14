BPF-based packet filtering framework
---

`bpfilter` is a daemon and shared library aiming to translate packets filtering rules into BPF programs.

## Build from sources

`bpfilter` requires an up-to-date system running Linux 6.4+ and `libbpf` 1.2+. Build dependencies are the following on Fedora 38:
```shell
sudo dnf install -y \
    cmake libbpf-devel \
    libcmocka-devel clang-tools-extra lcov \
    doxygen python3-sphinx python3-breathe python3-furo pkgconf
```

## Quick Start

Run from the source directory:
```shell
# Build bpfilter and libbpfilter
cmake -S . -B build
make -C build -j
# Run unit tests
make -C build test
```

`bpfilter` daemon will be in `$BUILD/src/bpfilter`, and `libbpfilter.so` will be in `$BUILD/lib/libbpfilter.so`.

## License

bpfilter is GPLv2 licensed, as found in the COPYING file.

`bpfilter` was originally developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).
