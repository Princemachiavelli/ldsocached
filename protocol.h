#ifndef NIX_LD_CACHE_PROTOCOL_H
#define NIX_LD_CACHE_PROTOCOL_H

#include <stdint.h>

#define NIX_LD_CACHE_PROTOCOL_MAGIC 0x4e4c4348u
#define NIX_LD_CACHE_PROTOCOL_VERSION 1u
#define NIX_LD_CACHE_PROTOCOL_MAX_FIELD 4096u

struct nix_ld_cache_msg {
  uint32_t magic;
  uint32_t version;
  uint32_t requester_len;
  uint32_t soname_len;
  uint32_t path_len;
};

#endif
