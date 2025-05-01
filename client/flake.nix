# nix develop --extra-experimental-features nix-command --extra-experimental-features flakes

{
  description = "amnezichat dev env";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }: flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };

      nativeDeps = with pkgs; [
        pkg-config
        openssl
        clang
        llvm
        libclang
        cmake
        xorg.libX11
        xorg.libXcursor
        xorg.libXrandr
        xorg.libXi
        libxkbcommon
        alsa-lib
        udev
        vulkan-loader
        vulkan-headers
        wayland
        mesa
        libGL
        fontconfig
        freetype
	glib
        gtk3
      ];
    in {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          rustc
          cargo
          rust-analyzer
        ] ++ nativeDeps;

        # needed for crates like `eframe` and GUI stuff
        shellHook = ''
          export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath nativeDeps}:$LD_LIBRARY_PATH
        '';
      };
    }
  );
}


