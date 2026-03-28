{
  fileset,
  go,
  ginkgo,
  buildGoApplication,
  version,
}:
let
  fs = fileset;
in
buildGoApplication {
  inherit go version;
  pname = "wireguard-cni";
  modules = ../gomod2nix.toml;

  ldflags = [
    "-s"
    "-w"
    "-X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=${version}"
  ];

  src = fs.toSource {
    root = ../.;
    fileset = fs.difference (fs.gitTracked ../.) (
      fs.unions [
        ../.editorconfig
        ../.gitignore
        ../.github
        ../.vscode
        ../nix
        ../flake.lock
        ../flake.nix
        ../Makefile
        (fs.fileFilter (f: f.hasExt "md") ../.)
      ]
    );
  };

  nativeCheckInputs = [ ginkgo ];

  checkPhase = ''
    ginkgo run -r --label-filter="!e2e"
  '';
}
