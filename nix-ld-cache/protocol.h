#ifndef NIX_LD_CACHE_PROTOCOL_H
#define NIX_LD_CACHE_PROTOCOL_H

/* Only freestanding headers: the audit module includes this without libc. */
#include <stdint.h>

#define NIX_LD_CACHE_PROTOCOL_MAGIC 0x4e4c4348u
#define NIX_LD_CACHE_PROTOCOL_VERSION 3u
#define NIX_LD_CACHE_PROTOCOL_MAX_FIELD 4096u

/* The client sends the cache scope, not the resolved path. The daemon still
 * derives the resolution and validates store-only search paths before writing. */
struct nix_ld_cache_msg {
  uint32_t magic;
  uint32_t version;
  uint32_t requester_len;
  uint32_t soname_len;
  uint32_t ld_library_path_len;
};

/* Read raw off the wire, so a padding-free layout must be guaranteed rather
 * than incidental. */
_Static_assert(sizeof(struct nix_ld_cache_msg) == 5 * sizeof(uint32_t),
               "nix_ld_cache_msg must be padding-free");

#endif
