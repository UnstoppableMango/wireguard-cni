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
        inherit pkgs version;
        inherit (lib) fileset;
        go = pkgs.go_1_26;
      };

      ctr = pkgs.callPackage ./container.nix {
        inherit pkgs version wireguard-cni;
      };
    in
    {
      packages = {
        inherit wireguard-cni ctr;
        default = wireguard-cni;
      };
    };
}
