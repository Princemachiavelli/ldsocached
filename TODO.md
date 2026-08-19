# TODO

- Store the unhashed scope key in each cache file and reject hash collisions instead of trusting the 64-bit FNV filename alone.
- Add SHA-256 hashing for the LD_LIBRARY_PATH portion of cache scope keys.
- Record more provenance for learned entries, including the search source and exact requester search-path context, so replay decisions are easier to validate.
- Consider encoding stronger ABI compatibility data than soname matching alone, such as versioned symbol requirements, before committing shared cache entries.
