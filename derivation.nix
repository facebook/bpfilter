{
  stdenv,
  lib,
  cmake,
  ninja,
  pkg-config,
  clang,
  bison,
  flex,
  libbpf,
  libnl,
  elfutils,
  openssl,
  testers,
  zlib,
  zstd,
  pcre2,
  xxd,
  version,
}:

let
  fs = lib.fileset;

  # zerocallusedregs is invalid with -target bpf
  hardeningDisable = [ "zerocallusedregs" ];

in
{
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
    ];

    buildInputs = [
      libbpf
      libnl
      elfutils
      openssl
      zlib
      zstd
      pcre2
      xxd
    ];

    cmakeFlags = [
      "-DNO_DOCS=1"
      "-DNO_TESTS=1"
      "-DNO_CHECKS=1"
      "-DNO_BENCHMARKS=1"
    ];

    # We do not run the unit tests because the nix build sandbox doesn't
    # have access to /sys/kernel/btf/vmlinux.
    doCheck = false;

    meta.pkgConfigModules = [ "bpfilter" ];

    passthru = {
      tests.pkg-config = testers.testMetaPkgConfig finalAttrs.finalPackage;
    };

    preFixup = ''
      substituteInPlace $out/lib/systemd/system/bpfilter.service \
        --replace-fail /usr/sbin/bpfilter $out/bin/bpfilter

      # workaround for https://github.com/NixOS/nixpkgs/issues/144170
      substituteInPlace $out/lib/pkgconfig/bpfilter.pc --replace-fail ''${prefix}/ ""
    '';
  });
}
