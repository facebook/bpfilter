<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="doc/_static/logo-dark-mode.png">
        <source media="(prefers-color-scheme: light)" srcset="doc/_static/logo-light-mode.png">
        <img src="doc/_static/logo-light-mode.png"  height="250" alt="bpfilter">
    </picture>
</p>

<h3 align="center">An <a href="https://ebpf.io/">eBPF</a>-based packet filtering framework.</h3>

**bpfilter** is an eBPF-based packet filtering framework designed to translate filtering rules into BPF programs. It comprises three main components:

1. A daemon that runs on the host, translating filtering rules into BPF programs.
2. A lightweight library to facilitate communication with the daemon.
3. A dedicated command line interface to define the filtering rules.

A typical usage workflow would be to start the `bpfilter` daemon, then define the filtering rules using `bfcli` (part of the `bpfilter` project), `nftables` or `iptables`. The `bpfilter` daemon will be responsible for translating the filtering rules into custom BPF programs, and loading them on the system.

Detailed information can be found in the [documentation](https://bpfilter.io).

## Quick start guide (Fedora 41)

1. **Install dependencies**
    ```shell
    # To build bpfilter
    sudo dnf install -y bison bpftool clang clang-tools-extra cmake doxygen flex g++ gcc git jq lcov libasan libbpf-devel libcmocka-devel libnl3-devel libubsan pkgconf python3-breathe python3-furo python3-linuxdoc python3-sphinx

    # To build nftables and iptables
    sudo dnf install -y autoconf automake git gmp-devel libtool libedit-devel libmnl-devel libnftnl-devel
    ```

2. **Build `bpfilter`**
    ```shell
    cmake -S $SOURCES_DIR -B $BUILD_DIR
    make -C $BUILD_DIR
    make -C $BUILD_DIR test
    ```

3. **Build custom versions of `nftables` and `iptables` (optional)**
    ```shell
    make -C $BUILD_DIR nftables iptables
    ```

4. **Start the `bpfilter` daemon**
    ```shell
    sudo $BUILD_DIR/src/bpfilter
    ```

5. **Configure the filtering rules**
    - For `bfcli`:
        ```shell
        $BUILD_DIR/output/bin/bfcli --file $RULESET
        ```
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
