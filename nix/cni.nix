{
  fileset,
  go,
  ginkgo,
  buildGoApplication,
  version,
}:
buildGoApplication {
  pname = "wireguard-cni";
  inherit go version;

  modules = ../gomod2nix.toml;
  src = fileset.toSource {
    root = ../.;
    fileset = fileset.difference (fileset.gitTracked ../.) (
      fileset.unions [
        ../.editorconfig
        ../.gitignore
        ../.github
        ../.vscode
        ../nix
        ../flake.lock
        ../flake.nix
        ../Makefile
        (fileset.fileFilter (f: f.hasExt "md") ../.)
      ]
    );
  };

  nativeCheckInputs = [ ginkgo ];

  checkPhase = ''
    ginkgo run -r --label-filter="!e2e"
  '';
}
