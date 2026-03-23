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
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;
      imports = [ inputs.treefmt-nix.flakeModule ];

      perSystem =
        {
          inputs',
          pkgs,
          lib,
          system,
          ...
        }:
        let
          inherit (inputs'.gomod2nix.legacyPackages) buildGoApplication;

          gopkg = pkgs.go_1_26;
          version = "0.0.1";
          wireguard-cni = buildGoApplication {
            pname = "wireguard-cni";
            inherit version;

            go = gopkg;
            src = lib.cleanSource ./.;
            modules = ./gomod2nix.toml;

            nativeBuildInputs = [ pkgs.ginkgo ];

            checkPhase = ''
              ginkgo run -r --label-filter="!e2e"
            '';
          };

          ctr = pkgs.dockerTools.streamLayeredImage {
            name = "wireguard-cni";
            tag = version;

            contents = pkgs.buildEnv {
              name = "image-root";
              paths = [ wireguard-cni ];
              pathsToLink = [ "/bin" ];
            };

            config = {
              Entrypoint = [ "/bin/wireguard-cni" ];
            };
          };
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.gomod2nix.overlays.default ];
          };

          packages = {
            inherit wireguard-cni ctr;
            default = wireguard-cni;
          };

          devShells.default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              docker
              ginkgo
              gnumake
              gopkg
              gomod2nix
              nixfmt
            ];

            DOCKER = "${pkgs.docker}/bin/docker";
            GINKGO = "${pkgs.ginkgo}/bin/ginkgo";
            GO = "${gopkg}/bin/go";
            GOMOD2NIX = "${pkgs.gomod2nix}/bin/gomod2nix";

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
