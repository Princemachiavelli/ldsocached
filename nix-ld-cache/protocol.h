#ifndef NIX_LD_CACHE_PROTOCOL_H
#define NIX_LD_CACHE_PROTOCOL_H

#include <assert.h>
#include <stdint.h>

#define NIX_LD_CACHE_PROTOCOL_MAGIC 0x4e4c4348u
#define NIX_LD_CACHE_PROTOCOL_VERSION 2u
#define NIX_LD_CACHE_PROTOCOL_MAX_FIELD 4096u

/* Version 2 drops the client-supplied path. The daemon derives the resolution
 * itself, so there is no claim to check and nothing the client says about the
 * answer can influence it. */
struct nix_ld_cache_msg {
  uint32_t magic;
  uint32_t version;
  uint32_t requester_len;
  uint32_t soname_len;
};

/* Read raw off the wire, so a padding-free layout must be guaranteed rather
 * than incidental. */
static_assert(sizeof(struct nix_ld_cache_msg) == 4 * sizeof(uint32_t),
              "nix_ld_cache_msg must be padding-free");

#endif
