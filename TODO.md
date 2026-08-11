# TODO

- Store the unhashed scope key in each cache file and reject hash collisions instead of trusting the 64-bit FNV filename alone.
- Record more provenance for learned entries, including the search source and exact requester search-path context, so replay decisions are easier to validate.
- Strengthen request correlation so `la_objopen` does not rely only on the current requester stack and candidate-path matching.
- Consider encoding stronger ABI compatibility data than soname matching alone, such as versioned symbol requirements, before committing shared cache entries.
