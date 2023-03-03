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

At present, the code statically sets the interface to which bpfilter is attached. However, there are plans to enhance this functionality in the future. As of now, you will need to make changes to `PROG_IFINDEX` in `codegen.c` if you want to modify the interface.

## License

bpfilter is GPLv2 licensed, as found in the COPYING file.

`bpfilter` was originally developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).
