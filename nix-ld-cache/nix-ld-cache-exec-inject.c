/* execve() interposer: makes nix-daemon splice the ldsocached audit
 * environment into every process it launches, sandboxed derivation builds
 * included.
 *
 * Nix only forwards nix.conf's `impure-env` to fixed-output derivations that
 * also declare the names in their own `impureEnvVars` (see initEnv() in
 * nix's src/libstore/unix/build/derivation-builder.cc) -- ordinary builds,
 * where the toolchain actually runs, never see it. This runs one layer
 * below that: nix-daemon calls execve() directly (never posix_spawn, see
 * that same file's execBuilder()) to launch the builder, after it has
 * already dropped privileges and chrooted. Interposing that call sees
 * whatever envp Nix decided on and can append to it -- Nix has no way to
 * detect or block that, since impure-env only gates what its own code
 * adds. Once LD_AUDIT is in the builder's environment, ordinary fork/exec
 * inheritance carries it to every process the builder itself spawns
 * (gcc, ld, ...), so only this one call needs to be caught.
 *
 * Unlike nix-ld-cache-audit.c, this is loaded only into nix-daemon's own
 * process (LD_PRELOAD via systemd.services.nix-daemon.environment), which
 * is built against the same glibc as this shim, so the two-glibc-families
 * hazard that keeps the audit module freestanding does not apply here --
 * this never gets mapped into an arbitrary, differently-linked target.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Space-separated names of the vars to propagate, e.g. "LD_AUDIT
 * NIX_LD_AUDIT_CACHE_DIR NIX_LD_AUDIT_SOCKET GLIBC_TUNABLES". Values come
 * from this process's own environment (set alongside this var, so
 * module.nix stays the single source of truth for the variable set). */
#define INJECT_VARS_ENV "NIX_LD_CACHE_INJECT_VARS"

typedef int (*execve_fn)(const char *, char *const[], char *const[]);

static execve_fn real_execve(void) {
    static execve_fn fn = NULL;
    if (fn == NULL) {
        fn = (execve_fn) dlsym(RTLD_NEXT, "execve");
    }
    return fn;
}

static size_t envp_len(char *const envp[]) {
    size_t n = 0;
    while (envp != NULL && envp[n] != NULL) {
        n++;
    }
    return n;
}

static bool envp_has(char *const envp[], const char *name, size_t name_len) {
    for (size_t i = 0; envp != NULL && envp[i] != NULL; i++) {
        if (strncmp(envp[i], name, name_len) == 0 && envp[i][name_len] == '=') {
            return true;
        }
    }
    return false;
}

/* Returns an envp with the configured vars appended, or NULL if there is
 * nothing to add (envp is then used unmodified). Only entries absent from
 * envp are added, so a derivation that set one of these itself wins. */
static char **build_augmented_envp(char *const envp[]) {
    const char *names = getenv(INJECT_VARS_ENV);
    if (names == NULL || names[0] == '\0') {
        return NULL;
    }

    char *names_copy = strdup(names);
    if (names_copy == NULL) {
        return NULL;
    }

    size_t max_extra = 1;
    for (const char *p = names_copy; *p != '\0'; p++) {
        if (*p == ' ') {
            max_extra++;
        }
    }

    size_t base = envp_len(envp);
    char **out = malloc((base + max_extra + 1) * sizeof(char *));
    if (out == NULL) {
        free(names_copy);
        return NULL;
    }
    for (size_t i = 0; i < base; i++) {
        out[i] = envp[i];
    }

    size_t n = base;
    char *save = NULL;
    for (char *tok = strtok_r(names_copy, " ", &save); tok != NULL; tok = strtok_r(NULL, " ", &save)) {
        size_t name_len = strlen(tok);
        if (name_len == 0 || envp_has(envp, tok, name_len)) {
            continue;
        }
        const char *value = getenv(tok);
        if (value == NULL) {
            continue;
        }
        size_t value_len = strlen(value);
        char *entry = malloc(name_len + 1 + value_len + 1);
        if (entry == NULL) {
            continue;
        }
        memcpy(entry, tok, name_len);
        entry[name_len] = '=';
        memcpy(entry + name_len + 1, value, value_len + 1);
        out[n++] = entry;
    }
    out[n] = NULL;
    free(names_copy);

    if (n == base) {
        free(out);
        return NULL;
    }
    return out;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    char **augmented = build_augmented_envp(envp);
    int rc = real_execve()(path, argv, augmented != NULL ? augmented : envp);

    /* Only reached if execve() failed; on success the address space is
     * already gone. */
    if (augmented != NULL) {
        for (size_t i = envp_len(envp); augmented[i] != NULL; i++) {
            free(augmented[i]);
        }
        free(augmented);
    }
    return rc;
}
