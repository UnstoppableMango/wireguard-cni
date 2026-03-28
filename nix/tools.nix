{
  bash,
  buildEnv,
  dockerTools,
  netcat,
  uutils-coreutils-noprefix,
  wireguard-tools,
}:
dockerTools.streamLayeredImage {
  name = "wireguard-cni-tools";
  tag = "latest";

  contents = buildEnv {
    name = "image-root";
    paths = [
      bash
      netcat
      uutils-coreutils-noprefix
      wireguard-tools
    ];
    pathsToLink = [ "/bin" ];
  };

  config = {
    Entrypoint = [ "/bin/bash" ];
  };
}
