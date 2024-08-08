# BPF-Based Packet Filtering Framework

**`bpfilter`** is a BPF-based packet filtering framework designed to translate filtering rules into BPF programs. It comprises two main components:
1. A daemon that runs on the host, translating filtering rules into BPF programs.
2. A lightweight library to facilitate communication with the daemon.

While `bpfilter` itself does not create filtering rules, this repository includes patches for `iptables` and `nftables` to integrate them with `bpfilter`. Detailed information can be found in the [documentation](https://bpfilter.io).

## Quick Start Guide

### Installation
> [!TIP]
> This guide is meant for systems running Fedora 38+

Follow these steps to get `bpfilter` up and running:

1. **Install Dependencies**
    ```shell
    sudo dnf install \
        clang-tools-extra \
        cmake \
        libcmocka-devel \
        doxygen \
        lcov \
        libasan \
        libbpf-devel \
        libnl3-devel \
        libubsan \
        python3-breathe \
        python3-furo \
        python3-sphinx \
        pkgconf
    ```

2. **Build `bpfilter`**
    ```shell
    cmake -S $SOURCES_DIR -B $BUILD_DIR
    make -C $BUILD_DIR
    make -C $BUILD_DIR test
    ```

3. **Build Custom Versions of `nftables` and `iptables`**
    ```shell
    make -C $BUILD_DIR nftables iptables
    ```

4. **Start the `bpfilter` Daemon**
    ```shell
    sudo $BUILD_DIR/src/bpfilter
    ```

5. **Run Custom Versions of `nftables` and `iptables`**
    - For `nftables`:
        ```shell
        sudo $BUILD_DIR/tools/install/sbin/nft --bpf ...
        ```
    - For `iptables`:
        ```shell
        sudo $BUILD_DIR/tools/install/sbin/iptables --bpf ...
        ```

## License

`bpfilter` is licensed under GPLv2. You can find the licensing details in the COPYING file.

## Acknowledgements

`bpfilter` was initially developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).

For further information and updates, visit the [bpfilter documentation](https://bpfilter.io).
