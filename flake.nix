{
  description = "vpnguin: vsock VPN bridge (guest + host) for penguin, cross-built for every guest arch";

  nixConfig = {
    extra-substituters = [ "https://rehosting-tools.cachix.org" ];
    extra-trusted-public-keys = [
      "rehosting-tools.cachix.org-1:iNKSaFwG7MfGn6Fk7oTmIcLHqfffQ+cQIE5gWc6MlY0="
    ];
  };

  # Pinned to the same nixpkgs commit as penguin / penguin-tools so the cross
  # toolchains and rust closures are byte-identical and shared through Cachix.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/b6067cc0127d4db9c26c79e4de0513e58d0c40c9";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      archMatrix = import ./src/archs.nix;

      pkgs = import nixpkgs {
        inherit system;
        config.allowUnsupportedSystem = true;
      };
      lib = pkgs.lib;

      mkMuslCrossPkgs = archKey:
        import nixpkgs {
          inherit system;
          config.allowUnsupportedSystem = true;
          crossSystem = archMatrix.${archKey}.muslCrossSystem;
        };

      # rust has no usable mips64 musl target (n64 muslabi64 is tier-3, no std),
      # so -- like the upstream Docker builds -- the mips64 guests reuse the
      # 32-bit mips Rust binary (o32 binaries run on 64-bit MIPS guests).
      rustBuildArch = archKey:
        {
          mips64eb = "mipseb";
          mips64el = "mipsel";
        }.${archKey} or archKey;

      # vpnguin: multi-call binary "vsock_vpn" (penguin renames it "vpn"). Guest
      # runs `vpn guest` (all arches); host runs `vpn host` from the x86_64 build
      # (its pcap deps are cfg(x86_64/aarch64)-gated, compiled in automatically).
      mkVpnguin = archKey:
        import ./src/mk-guest-rust-tool.nix {
          crossPkgs = mkMuslCrossPkgs (rustBuildArch archKey);
          src = self;
          pname = "vsock_vpn";
          version = "0.1.2";
        };
      vpnguinBins = lib.mapAttrs (archKey: _: mkVpnguin archKey) archMatrix;

      # Per-arch packages exposed individually for partial builds / debugging.
      perArchPackages = builtins.listToAttrs (
        lib.mapAttrsToList
          (archKey: _: {
            name = "vpnguin-${archMatrix.${archKey}.penguinName}";
            value = vpnguinBins.${archKey};
          })
          archMatrix
      );

      # dist: exactly the fragment of /igloo_static this tool owns, so penguin
      # can `cp -a ${vpnguin}/. igloo_static/` and let its existing staging loop
      # generate the rest. Mirrors penguin-tools/src/mk-dist-root.nix vpn staging:
      #   <penguinName>/vpn                    guest binary (melting-pot dir)
      #   vpn/vpn.<penguinName> -> ../<pn>/vpn  flat link (host reads vpn.x86_64)
      #   vpn/vpn.<compat>      -> ../<pn>/vpn  legacy arch-name aliases
      dist = pkgs.runCommand "vpnguin-dist"
        {
          nativeBuildInputs = with pkgs.buildPackages; [ coreutils ];
        }
        ''
          set -euo pipefail
          mkdir -p "$out/vpn"
          ${lib.concatStringsSep "\n" (
            lib.mapAttrsToList
              (archKey: _:
                let
                  spec = archMatrix.${archKey};
                  pn = spec.penguinName;
                  compatNames = spec.compatNames or [ ];
                  vpn = vpnguinBins.${archKey};
                in
                ''
                  mkdir -p "$out/${pn}"
                  cp ${vpn}/bin/vsock_vpn "$out/${pn}/vpn"
                  ln -sfn "../${pn}/vpn" "$out/vpn/vpn.${pn}"
                  ${lib.concatMapStringsSep "\n"
                    (compat: ''ln -sfn "../${pn}/vpn" "$out/vpn/vpn.${compat}"'')
                    compatNames}
                '')
              archMatrix
          )}
          chmod -R u+w "$out"
        '';
    in
    {
      packages.${system} = perArchPackages // {
        inherit dist;
        default = dist;
      };

      checks.${system} = {
        inherit dist;
      };
    };
}
