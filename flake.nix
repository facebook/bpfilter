{
  description = "bpfilter - eBPF-based packet filtering framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/master";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });

      version = "0.0.1";

    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          bpfilterLib = pkgs.callPackage ./derivation.nix { inherit version; };
        in
        {
          default = bpfilterLib.package;
          bpfilter = bpfilterLib.package;
        }
      );

      formatter = forAllSystems (system: nixpkgsFor.${system}.nixfmt-rfc-style);

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          bpfilterLib = pkgs.callPackage ./derivation.nix { inherit version; };
        in
        {
          default = pkgs.mkShell {
            name = "bpfilter-dev";

            inherit (bpfilterLib) hardeningDisable;

            inputsFrom = [ bpfilterLib.package ];

            packages = with pkgs; [
              gnumake
              clang-tools # clang-tidy, clang-format
              include-what-you-use
              gcc
              autoconf
              automake
              libtool

              # Git (for GitVersion.cmake and benchmarks)
              git
              libgit2

              # BPF tools
              bpftools

              # Networking tools (for e2e tests)
              iproute2
              iputils

              # Testing
              cmocka
              gbenchmark

              # Utilities
              gawk
              jq
              gnused
              procps
              lcov

              # Documentation
              doxygen
              python3
              python3Packages.sphinx
              python3Packages.breathe
              python3Packages.furo
              python3Packages.linuxdoc
              python3Packages.setuptools
            ];

            shellHook = ''
              # Set locale for sphinx-build
              export LOCALE_ARCHIVE="${pkgs.glibcLocales}/lib/locale/locale-archive"
              export LC_ALL=C.UTF-8

              # Add libbpf headers to include path for clang-tidy
              export CPATH="${pkgs.libbpf}/include''${CPATH:+:$CPATH}"

              echo "bpfilter development environment"
            '';
          };
        }
      );
    };
}
