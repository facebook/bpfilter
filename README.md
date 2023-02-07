BPF-based packet filtering framework
---

`bpfilter.ko` is an out-of-tree kernel module catching `setsockopt()` requests coming from `iptables-legacy` and converting the rules into BPF programs.

`CONFIG_BPFILTER` needs to be enabled.

To build the kernel module:
```shell
make \
	-C $SOURCE_DIR \
	O=$BUILD_DIR \
	M=$PATH_TO_BPFILTER_SOURCES
```


## License

bpfilter is GPLv2 licensed, as found in the COPYING file.

`bpfilter` was originally developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).
