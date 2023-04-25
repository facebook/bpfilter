BPF-based packet filtering framework
---

`bpfilter` is a daemon and shared library aiming to translate filtering rules into BPF programs, improve performances.

## Build from sources

Building `bpfilter` will requires the following packages:

```shell
sudo dnf install -y \
	cmake \
	# Formatting and code quality: not required by advised
	clang-tools-extra \
	# For unit tests
	gtest-devel lcov libasan libubsan \
	# For documentation
	doxygen python3-sphinx python3-breathe python3-furo
```

At present, the code statically sets the interface to which bpfilter is attached. However, there are plans to enhance this functionality in the future. As of now, you will need to make changes to `PROG_IFINDEX` in `codegen.c` if you want to modify the interface.

## License

bpfilter is GPLv2 licensed, as found in the COPYING file.

`bpfilter` was originally developed by Dmitrii Banshchikov as a [Linux kernel usermode helper](https://lore.kernel.org/bpf/20210829183608.2297877-1-me@ubique.spb.ru/).
