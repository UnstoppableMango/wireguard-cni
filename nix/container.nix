{
  bash,
  buildEnv,
  dockerTools,
  uutils-coreutils-noprefix,
  wireguard-cni,
  ...
}:
dockerTools.streamLayeredImage {
  name = "wireguard-cni";
  tag = "latest";

  contents = buildEnv {
    name = "image-root";
    paths = [
      wireguard-cni
      bash
      uutils-coreutils-noprefix
    ];
    pathsToLink = [ "/bin" ];
  };

  config = {
    Entrypoint = [ "/bin/wireguard-cni" ];
  };
}
