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

        mkSniffit = { lib, stdenv, autoreconfHook, libpcap, ncurses, withInteractive ? true }:
          stdenv.mkDerivation (finalAttrs: {
            pname = "sniffit";
            version = "0.7";

            src = ./.;

            nativeBuildInputs = [ autoreconfHook ];

            buildInputs = [ libpcap ]
              ++ lib.optionals withInteractive [ ncurses ];

            postInstall = ''
              install -Dm644 docs/README.FIRST -t $out/share/doc/sniffit/
              install -Dm644 docs/PLUGIN-HOWTO -t $out/share/doc/sniffit/
              install -Dm644 docs/sniffit-FAQ -t $out/share/doc/sniffit/
            '';

            meta = with lib; {
              description = "Historical packet sniffer and network monitoring tool";
              longDescription = ''
                Sniffit is a packet sniffer for TCP/UDP/ICMP packets over IPv4.
                It provides detailed technical information on packets including SEQ, ACK,
                TTL, Window, and displays packet contents in hex or plain text formats.
                Originally developed by Brecht Claerhout (1996-1998), now maintained
                as part of the "Resurrecting Open Source Projects" initiative.

                Note: Requires root privileges for packet capture operations.
              '';
              homepage = "https://github.com/resurrecting-open-source-projects/sniffit";
              license = licenses.bsd3;
              platforms = platforms.unix;
              maintainers = [ ];
              mainProgram = "sniffit";
            };

            passthru.tests = {
              version = pkgs.runCommand "sniffit-version-test" {} ''
                ${finalAttrs.finalPackage}/bin/sniffit -v > $out
                grep -q "0.7" $out
              '';

              documentation = pkgs.runCommand "sniffit-docs-test" {} ''
                test -f ${finalAttrs.finalPackage}/share/doc/sniffit/README.FIRST
                test -f ${finalAttrs.finalPackage}/share/doc/sniffit/PLUGIN-HOWTO
                test -f ${finalAttrs.finalPackage}/share/doc/sniffit/sniffit-FAQ
                test -f ${finalAttrs.finalPackage}/share/man/man8/sniffit.8.gz
                test -f ${finalAttrs.finalPackage}/share/man/man5/sniffit.5.gz
                touch $out
              '';

              minimal-build = pkgs.callPackage mkSniffit { withInteractive = false; };
            };
          });
      in
      {
        packages = rec {
          default = sniffit;
          sniffit = pkgs.callPackage mkSniffit { };
          sniffit-minimal = pkgs.callPackage mkSniffit { withInteractive = false; };
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
