let
  pkgs = import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/cf5e76507c6e23b59f7e0ffcc7baa2a39ddd8442.tar.gz";
    sha256 = "sha256-F+b8u43BVF5DlM0pz7JQSbtbwKy5PrHIT5zQUekXsD0=";
  }) { };
in
pkgs.mkShell {
  packages = [
    pkgs.rustup
    pkgs.trunk
  ];
}
