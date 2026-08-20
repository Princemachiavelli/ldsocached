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
  # DynamicUser= derives both a user and a group from the unit name, so the
  # shared group must not collide with it (that fails at step USER with
  # "User or group with specified name already exists").
  cacheGroup = "nix-ld-cache-readers";
  auditLibraryPath = "/run/current-system/sw/lib/nix-ld-cache.so";
  execInjectLibraryPath = "/run/current-system/sw/lib/nix-ld-cache-execinject.so";
  auditEnvironment = {
    LD_AUDIT = auditLibraryPath;
    NIX_LD_AUDIT_CACHE_DIR = cfg.cacheDir;
    NIX_LD_AUDIT_SOCKET = cfg.socketPath;
    GLIBC_TUNABLES = "glibc.rtld.optional_static_tls=${toString cfg.staticTlsSurplus}";
  }
  // lib.optionalAttrs cfg.debug {
    NIX_LD_AUDIT_DEBUG = "1";
  };
  auditEnvironmentString = lib.concatStringsSep " " (
    lib.mapAttrsToList (name: value: "${name}=${lib.escapeShellArg value}") auditEnvironment
  );
  # nix-daemon's own execve() interposer (nix-ld-cache-exec-inject.c) reads
  # this to know which of its own env vars to splice into every process it
  # launches, sandboxed builds included -- nix.conf's impure-env only ever
  # reaches fixed-output derivations that also opt in via impureEnvVars, so
  # it cannot do this. Derived from auditEnvironment so no variable, and
  # crucially not LD_PRELOAD itself, can be missed or wrongly included.
  daemonExecInjectEnvironment = {
    LD_PRELOAD = execInjectLibraryPath;
    NIX_LD_CACHE_INJECT_VARS = lib.concatStringsSep " " (lib.attrNames auditEnvironment);
  };
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
      description = "Expose the shared cache and daemon socket to Nix sandboxes, and make nix-daemon inject the audit environment into every process it execs, including sandboxed derivation builds.";
    };

    staticTlsSurplus = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 16384;
      description = ''
        Bytes added to glibc's optional static TLS surplus via
        `glibc.rtld.optional_static_tls`.

        Loading any `LD_AUDIT` module reserves an extra link-map namespace, which
        consumes part of the fixed static TLS surplus (`_dl_tls_static_surplus_init`
        in glibc's `elf/dl-tls.c` adds the audit count to `nns`). Libraries that
        need initial-exec TLS at `dlopen` time then fail with "cannot allocate
        memory in static TLS block" — Determinate Nix hits this on `libnixexpr.so`
        and `libjemalloc.so`, which breaks `nix-daemon` outright.

        Measured threshold for Determinate Nix 3.20.0 is between 7168 and 7680
        bytes; the default leaves headroom. Raise it if other `dlopen`ed
        initial-exec TLS consumers fail the same way.
      '';
    };

    debug = lib.mkEnableOption "debug logging for nix-ld-cache";
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # The shared cache must be world-readable: every audited process reads it
    # directly, and a read that fails makes the cache write-only. It is therefore
    # managed by tmpfiles rather than CacheDirectory=, which under DynamicUser=
    # would place the real directory under /var/cache/private (mode 0700, root)
    # and make it unreadable for exactly the clients it exists to serve.
    users.groups.${cacheGroup} = { };

    systemd.tmpfiles.settings.${runtimeName}.${cfg.cacheDir}.d = {
      user = "root";
      group = cacheGroup;
      mode = "0775";
    };

    environment.sessionVariables = auditEnvironment;

    systemd.settings.Manager.DefaultEnvironment = auditEnvironmentString;
    systemd.user.settings.Manager.DefaultEnvironment = auditEnvironmentString;

    nix.settings = lib.mkIf cfg.nixSandboxIntegration {
      # Bind-mounted into every sandboxed build's chroot so the builder
      # process (once execve() has the LD_AUDIT env var, see
      # daemonExecInjectEnvironment below) can actually open the audit
      # module and reach the daemon socket from inside the sandbox.
      extra-sandbox-paths = [
        cfg.cacheDir
        auditLibraryPath
        "/run/${runtimeName}"
      ];
    };

    systemd.services.nix-daemon.environment = lib.mkIf cfg.nixSandboxIntegration (
      auditEnvironment // daemonExecInjectEnvironment
    );

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
      # DefaultDependencies=false means nothing else pulls these in, and the
      # shared cache directory does not exist until tmpfiles has run.
      wants = [
        "local-fs.target"
        "systemd-tmpfiles-setup.service"
      ];
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/nix-ld-cache-daemon --socket ${lib.escapeShellArg cfg.socketPath} --cache-dir ${lib.escapeShellArg cfg.cacheDir}${lib.optionalString cfg.debug " --debug"}";
        Restart = "on-failure";
        RestartSec = 1;
        # Cleared so the daemon never audits itself. GLIBC_TUNABLES is only
        # needed to offset the audit module's TLS reservation, which does not
        # apply here.
        Environment = [
          "LD_AUDIT="
          "NIX_LD_AUDIT_CACHE_DIR="
          "NIX_LD_AUDIT_SOCKET="
          "NIX_LD_AUDIT_DEBUG="
          "GLIBC_TUNABLES="
        ];
        DynamicUser = true;
        # Writes must land group-writable-by-default so the group grant is what
        # actually governs access, and world-readable so clients can read them.
        UMask = "0002";
        # Group membership, not CacheDirectory=, is what grants write access to
        # the tmpfiles-managed shared cache; ProtectSystem=strict makes /var
        # read-only, so the path must be listed explicitly.
        SupplementaryGroups = [ cacheGroup ];
        ReadWritePaths = [ cfg.cacheDir ];
        RuntimeDirectory = runtimeName;
        RuntimeDirectoryMode = "0755";
        # One client fd per connection, plus the listening socket and epoll fd.
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
        CapabilityBoundingSet = [ "" ];
      };
    };
  };
}
