{
  description = "A Nix flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    systems.url = "github:nix-systems/default";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.inputs.systems.follows = "systems";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    let
      version = "0.0.1";
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;

      imports = [
        inputs.treefmt-nix.flakeModule
        (import ./nix { inherit version; })
      ];

      perSystem =
        { pkgs, system, ... }:
        let
          gopkg = pkgs.go_1_26;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.gomod2nix.overlays.default ];
          };

          devShells.default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              ginkgo
              gnumake
              gopkg
              gomod2nix
              kind
              kubectl
              nixfmt
              podman
              skopeo
            ];

            GINKGO = "${pkgs.ginkgo}/bin/ginkgo";
            GO = "${gopkg}/bin/go";
            GOMOD2NIX = "${pkgs.gomod2nix}/bin/gomod2nix";
            KIND = "${pkgs.kind}/bin/kind";
            KUBECTL = "${pkgs.kubectl}/bin/kubectl";
            SKOPEO = "${pkgs.skopeo}/bin/skopeo";

            KIND_EXPERIMENTAL_PROVIDER = "podman";
            VERSION = version;
            GOVERSION = gopkg.version;
          };

          treefmt.programs = {
            actionlint.enable = true;
            gofmt.enable = true;
            nixfmt.enable = true;
          };
        };
    };
}
