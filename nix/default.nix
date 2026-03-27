{ version, ... }:
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

      ctr = pkgs.callPackage ./container.nix {
        inherit wireguard-cni;
      };
    in
    {
      packages = {
        inherit wireguard-cni ctr;
        default = wireguard-cni;
      };
    };
}
