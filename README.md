BPF-based packet filtering framework
---

`bpfilter` is a daemon and shared library aiming to translate packets filtering rules into BPF programs.

## Build from sources

Building and running `bpfilter` requires `libbpf` version 1.0 or above, and Linux 5.19+. `bpfilter` is developed (and tested) on Fedora 38, with `libbpf` 1.1 and Linux 6.2.

Building `bpfilter` requires the following packages on Fedora 38:

```shell
# Install dependencies
sudo dnf install -y \
    cmake libbpf-devel \
    libcmocka-devel clang-tools-extra lcov \
    doxygen python3-sphinx python3-breathe python3-furo
```

To build `bpfilter` (from the source directory):
```shell
cmake -Bbuild -S.
make -C build -j
```

`bpfilter` daemon will be in `$BUILD/src/bpfilter`, and `libbpfilter.so` will be in `$BUILD/lib/libbpfilter.so`.

## License

bpfilter is GPLv2 licensed, as found in the COPYING file.

`bpfilter` was originally developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).
