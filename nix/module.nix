{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.mempool-radar;
  inherit (lib)
    escapeShellArgs
    mkEnableOption
    mkIf
    mkOption
    optional
    types
    ;

  command = escapeShellArgs (
    [
      "${cfg.package}/bin/mempool-radar"
      "--network"
      cfg.network
      "--rpc-url"
      cfg.rpcUrl
      "--zmq-endpoint"
      cfg.zmqEndpoint
      "--large-tx-size"
      (toString cfg.largeTransactionSize)
      "--max-ancestors"
      (toString cfg.maxAncestors)
      "--max-descendants"
      (toString cfg.maxDescendants)
      "--max-package-size"
      (toString cfg.maxPackageSize)
    ]
    ++ optional (cfg.cookieFile != null) "--cookie-file"
    ++ optional (cfg.cookieFile != null) cfg.cookieFile
    ++ optional cfg.sendStartupMessage "--send-startup-message"
    ++ cfg.extraArgs
  );
in
{
  options.services.mempool-radar = {
    enable = mkEnableOption "Mempool Radar";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "mempool-radar.packages.\${pkgs.system}.default";
      description = "The Mempool Radar package to run.";
    };

    user = mkOption {
      type = types.str;
      default = "mempool-radar";
      description = "User under which the service runs.";
    };

    group = mkOption {
      type = types.str;
      default = "mempool-radar";
      description = "Group under which the service runs.";
    };

    network = mkOption {
      type = types.enum [
        "bitcoin"
        "testnet"
        "testnet4"
        "signet"
        "regtest"
      ];
      default = "bitcoin";
      description = "Bitcoin network monitored by the service.";
    };

    rpcUrl = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8332";
      description = "Bitcoin Core RPC URL.";
    };

    zmqEndpoint = mkOption {
      type = types.str;
      default = "tcp://127.0.0.1:28332";
      description = "Bitcoin Core ZMQ sequence endpoint.";
    };

    cookieFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/var/lib/bitcoind/.cookie";
      description = ''
        Bitcoin Core authentication cookie. When unset, Mempool Radar uses
        the standard cookie location for the service user's home directory.
      '';
    };

    environmentFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/secrets/mempool-radar.env";
      description = ''
        Environment file containing secrets such as
        MEMPOOL_RADAR_TELEGRAM_TOKEN. This should be a runtime path rather
        than a file in the Nix store.
      '';
    };

    logLevel = mkOption {
      type = types.str;
      default = "info,mempool_radar=debug";
      description = "Tracing filter passed through RUST_LOG.";
    };

    largeTransactionSize = mkOption {
      type = types.ints.positive;
      default = 100000;
      description = "Transaction size in bytes at which an alert is emitted.";
    };

    maxAncestors = mkOption {
      type = types.ints.unsigned;
      default = 64;
      description = "Maximum ancestor count before a transaction is flagged.";
    };

    maxDescendants = mkOption {
      type = types.ints.unsigned;
      default = 64;
      description = "Maximum descendant count before a transaction is flagged.";
    };

    maxPackageSize = mkOption {
      type = types.ints.positive;
      default = 101000;
      description = "Maximum transaction package size in bytes.";
    };

    sendStartupMessage = mkOption {
      type = types.bool;
      default = false;
      description = "Send a notification when the service starts.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "--nostr-relays"
        "wss://relay.damus.io,wss://nos.lol"
      ];
      description = "Additional command-line arguments passed to Mempool Radar.";
    };
  };

  config = mkIf cfg.enable {
    users.groups.mempool-radar = mkIf (cfg.group == "mempool-radar") { };
    users.users.mempool-radar = mkIf (cfg.user == "mempool-radar") {
      isSystemUser = true;
      group = cfg.group;
    };

    systemd.services.mempool-radar = {
      description = "Bitcoin mempool anomaly monitor";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment.RUST_LOG = cfg.logLevel;

      serviceConfig = {
        ExecStart = command;
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        RestartSec = "5s";

        EnvironmentFile = mkIf (cfg.environmentFile != null) cfg.environmentFile;

        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = "read-only";
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
