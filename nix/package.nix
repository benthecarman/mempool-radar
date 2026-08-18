{
  lib,
  openssl,
  pkg-config,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "mempool-radar";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.lock
      ../Cargo.toml
      ../src
      ../tests
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];

  # The integration-test-only corepc-node dependency downloads a Bitcoin Core
  # binary in its build script, which is intentionally unavailable in a
  # sandboxed Nix build. The regular application build remains fully offline.
  doCheck = false;

  meta = {
    description = "Bitcoin mempool anomaly monitoring service";
    homepage = "https://github.com/benthecarman/mempool-radar";
    license = lib.licenses.mit;
    mainProgram = "mempool-radar";
    platforms = lib.platforms.linux;
  };
}
