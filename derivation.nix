{
  stdenv,
  lib,
  cmake,
  ninja,
  pkg-config,
  clang,
  bison,
  flex,
  git,
  libbpf,
  libnl,
  libgit2,
  elfutils,
  openssl,
  zlib,
  zstd,
  pcre2,
  xxd,
  version ? "0.0.1",
}:

let
  fs = lib.fileset;

  # zerocallusedregs is invalid with -target bpf
  hardeningDisable = [ "zerocallusedregs" ];

in {
  inherit hardeningDisable;

  package = stdenv.mkDerivation (finalAttrs: {
    pname = "bpfilter";
    inherit version;

    src = fs.toSource {
      root = ./.;
      fileset = fs.unions [
        ./src
        ./CMakeLists.txt
        ./tools/cmake
      ];
    };

    inherit hardeningDisable;

    nativeBuildInputs = [
      cmake
      ninja
      pkg-config
      clang # for building codegen BPF progs
      bison
      flex
      git
    ];

    buildInputs = [
      libbpf
      libnl
      libgit2
      elfutils
      openssl
      zlib
      zstd
      pcre2
      xxd
    ];

    cmakeFlags = [
      "-DDEFAULT_PROJECT_VERSION=${finalAttrs.version}"
      "-DNO_DOCS=1"
      "-DNO_TESTS=1"
      "-DNO_CHECKS=1"
      "-DNO_BENCHMARKS=1"
    ];

    # We do not run the unit tests because the nix build sandbox doesn't
    # have access to /sys/kernel/btf/vmlinux.
    doCheck = false;

    preFixup = ''
      substituteInPlace $out/lib/systemd/system/bpfilter.service \
        --replace-fail /usr/sbin/bpfilter $out/bin/bpfilter

      # workaround for https://github.com/NixOS/nixpkgs/issues/144170
      substituteInPlace $out/lib/pkgconfig/bpfilter.pc --replace-fail ''${prefix}/ ""
    '';
  });
}
