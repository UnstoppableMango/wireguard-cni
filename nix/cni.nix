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
  pname = "wireguard-cni";
  inherit go version;

  modules = ../gomod2nix.toml;
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
