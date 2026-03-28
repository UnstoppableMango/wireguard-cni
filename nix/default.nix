{ version }:
{
  perSystem =
    {
      inputs',
      pkgs,
      lib,
      ...
    }:
    let
      wireguard-cni = pkgs.callPackage ./cni.nix {
        inherit version;
        inherit (lib) fileset;
        inherit (inputs'.gomod2nix.legacyPackages) buildGoApplication;
        go = pkgs.go_1_26;
      };

      wireguard-cni-arm64 = wireguard-cni.overrideAttrs (_: {
        GOARCH = "arm64";
        CGO_ENABLED = "0";
        doCheck = false;
      });

      ctr = pkgs.callPackage ./container.nix {
        inherit wireguard-cni;
      };

      ctrtools = pkgs.callPackage ./tools.nix { };
    in
    {
      packages = {
        inherit
          wireguard-cni
          wireguard-cni-arm64
          ctr
          ctrtools
          ;

        default = wireguard-cni;
      };
    };
}
