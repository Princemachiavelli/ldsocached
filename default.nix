{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.nix-ld-cache;
  # Single source of truth for CacheDirectory=/RuntimeDirectory= and the paths
  # derived from them.
  runtimeName = "nix-ld-cache";
  auditEnvironment =
    {
      LD_AUDIT = "${cfg.package}/lib/libnix-ld-cache-audit.so";
      NIX_LD_AUDIT_CACHE_DIR = cfg.cacheDir;
      NIX_LD_AUDIT_SOCKET = cfg.socketPath;
    }
    // lib.optionalAttrs cfg.debug {
      NIX_LD_AUDIT_DEBUG = "1";
    };
  auditEnvironmentString = lib.concatStringsSep " " (
    lib.mapAttrsToList (name: value: "${name}=${lib.escapeShellArg value}") auditEnvironment
  );
in
{
  options.programs.nix-ld-cache = {
    enable = lib.mkEnableOption "the nix-ld-cache LD_AUDIT resolver cache";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.nix-ld-cache;
      defaultText = lib.literalExpression "pkgs.nix-ld-cache";
      description = "Package providing the nix-ld-cache audit shared object.";
    };

    cacheDir = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "/var/cache/${runtimeName}";
      description = "Shared cache root for resolved library paths. Fixed by the hardened service's CacheDirectory=.";
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "/run/${runtimeName}/learn.sock";
      description = "Unix socket path used by the privileged cache writer. Fixed by the hardened service's RuntimeDirectory=.";
    };

    nixSandboxIntegration = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Expose the shared cache and daemon socket to Nix sandboxes and configure nix-daemon to export the audit environment.";
    };

    debug = lib.mkEnableOption "debug logging for nix-ld-cache";
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          !cfg.nixSandboxIntegration
          || lib.elem "configurable-impure-env" (config.nix.settings.experimental-features or [ ]);
        message = "programs.nix-ld-cache.nixSandboxIntegration sets nix.settings.impure-env, which requires the configurable-impure-env experimental feature. Add it to nix.settings.experimental-features or set nixSandboxIntegration = false.";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    environment.sessionVariables = auditEnvironment;

    systemd.settings.Manager.DefaultEnvironment = auditEnvironmentString;
    systemd.user.settings.Manager.DefaultEnvironment = auditEnvironmentString;

    nix.settings = lib.mkIf cfg.nixSandboxIntegration {
      extra-sandbox-paths = [
        cfg.cacheDir
        "/run/${runtimeName}"
      ];
      impure-env = [
        "LD_AUDIT=${auditEnvironment.LD_AUDIT}"
        "NIX_LD_AUDIT_CACHE_DIR=${auditEnvironment.NIX_LD_AUDIT_CACHE_DIR}"
        "NIX_LD_AUDIT_SOCKET=${auditEnvironment.NIX_LD_AUDIT_SOCKET}"
      ]
      ++ lib.optional cfg.debug "NIX_LD_AUDIT_DEBUG=1";
    };

    systemd.services.nix-daemon.environment = lib.mkIf cfg.nixSandboxIntegration auditEnvironment;

    systemd.services.nix-ld-cache = {
      description = "nix-ld-cache privileged cache writer";
      wantedBy = [ "basic.target" ];
      before = [
        "basic.target"
        "nix-daemon.service"
      ];
      after = [
        "local-fs.target"
        "systemd-tmpfiles-setup.service"
      ];
      wants = [ "local-fs.target" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/nix-ld-cache-daemon --socket ${lib.escapeShellArg cfg.socketPath} --cache-dir ${lib.escapeShellArg cfg.cacheDir}${lib.optionalString cfg.debug " --debug"}";
        Restart = "on-failure";
        RestartSec = 1;
        Environment = [
          "LD_AUDIT="
          "NIX_LD_AUDIT_CACHE_DIR="
          "NIX_LD_AUDIT_SOCKET="
          "NIX_LD_AUDIT_DEBUG="
        ];
        DynamicUser = true;
        UMask = "0022";
        CacheDirectory = runtimeName;
        CacheDirectoryMode = "0755";
        RuntimeDirectory = runtimeName;
        RuntimeDirectoryMode = "0755";
        # One fd-table slot per connection is not enough: each also holds a
        # /proc/<pid> dirfd and a pidfd.
        LimitNOFILE = 4096;
        PermissionsStartOnly = false;
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectClock = true;
        MemoryDenyWriteExecute = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        SystemCallArchitectures = "native";
        RestrictAddressFamilies = [ "AF_UNIX" ];
        # /proc/<pid>/environ is gated by PTRACE_MODE_READ (see environ_open in
        # fs/proc/base.c), so reading a peer's LD_LIBRARY_PATH needs
        # CAP_SYS_PTRACE in addition to CAP_DAC_READ_SEARCH.
        CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" "CAP_SYS_PTRACE" ];
        AmbientCapabilities = [ "CAP_DAC_READ_SEARCH" "CAP_SYS_PTRACE" ];
      };
    };
  };
}
