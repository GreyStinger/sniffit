{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { flake-utils, nixpkgs, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = { };
        };
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "sniffit";
          version = "0.7";

          src = ./.;

          nativeBuildInputs = [ pkgs.autoreconfHook ];
          buildInputs = with pkgs; [
            libpcap
            ncurses
          ];

          configureFlags = [ ];
        };

        devShells.default = pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
          name = "sniffit-dev";

          packages = with pkgs; [ zsh ];

          nativeBuildInputs = with pkgs; [
            autoconf
            automake
            libpcap
            libtool
            ncurses
            pkg-config
            clang-tools
            shellcheck
            reuse
          ];

          shellHook = "
            exec ${pkgs.zsh}/bin/zsh
          ";
        };
      }
    );
}
