/* Freestanding LD_AUDIT module: replays cached soname resolutions for Nix
 * store binaries and reports misses to the nix-ld-cache daemon.
 *
 * This object must keep zero DT_NEEDED entries. When LD_AUDIT points at a
 * module that links glibc, the target's loader maps and relocates that glibc
 * before any audit hook can opt out; a process built against a different
 * glibc revision then carries two glibc families and dies before la_version
 * runs (see SYSCALL_ONLY.md). So: no libc calls of any kind — raw syscalls
 * via linux-syscall.h, fixed buffers plus a never-freed mmap arena instead of
 * malloc, a futex lock instead of pthreads, and /proc/self/environ instead of
 * getenv.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "linux-syscall.h"
#include "protocol.h"

#define STORE_PREFIX "/nix/store/"
#define RUN_PREFIX "/run/"
#define SCOPE_CACHE_CAP 16
/* Longest path (or protocol field) we handle, including the NUL. Anything
 * larger is uncacheable anyway: the submit protocol caps fields at
 * NIX_LD_CACHE_PROTOCOL_MAX_FIELD, so the daemon can never learn a scope the
 * fixed buffers cannot hold. */
#define PATH_BUF (NIX_LD_CACHE_PROTOCOL_MAX_FIELD + 1)
/* Cache-file paths append "/<16 hex>.tsv" to the configured cache root. */
#define CACHE_PATH_BUF (PATH_BUF + 32)
/* /proc/self/environ snapshot ceiling; the kernel caps env+argv well below
 * this. Virtual reservation only — untouched pages cost nothing. */
#define ENV_MAP_SIZE (4u << 20)
#define ARENA_CHUNK (64u * 1024u)

#ifndef NIX_LD_AUDIT_ENABLE_DEBUG
#define NIX_LD_AUDIT_ENABLE_DEBUG 0
#endif
#ifndef NIX_LD_AUDIT_ENABLE_DAEMONLESS
#define NIX_LD_AUDIT_ENABLE_DAEMONLESS 0
#endif

/* Minimal ELF and rtld-audit ABI, normally from <elf.h>/<link.h>. Defined
 * locally so no glibc header has to agree with the freestanding build. */
#define LNX_DT_NULL 0
#define LNX_DT_STRTAB 5
#define LNX_DT_STRSZ 10
#define LNX_DT_SONAME 14
#define LNX_DT_RPATH 15
#define LNX_DT_RUNPATH 29

#define LNX_PT_LOAD 1
#define LNX_PT_DYNAMIC 2
#define LNX_EI_CLASS 4
#define LNX_EI_DATA 5
#define LNX_ELFCLASS64 2
#define LNX_ELFDATA2LSB 1

/* LAV_CURRENT as of glibc 2.35+; older loaders negotiate down in la_version. */
#define NIX_LAV_CURRENT 2u
#define LNX_LA_SER_ORIG 0x01u

struct lnx_elf64_dyn {
  int64_t d_tag;
  uint64_t d_un;
};

struct lnx_elf64_ehdr {
  unsigned char e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct lnx_elf64_phdr {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

/* Public prefix of glibc's struct link_map; stable ABI. */
struct lnx_link_map {
  uint64_t l_addr;
  char *l_name;
  struct lnx_elf64_dyn *l_ld;
  struct lnx_link_map *l_next;
  struct lnx_link_map *l_prev;
};

/* One cached file per requester scope. A small LRU keeps repeated or revisited
 * scopes from paying another open/mmap while the process is resolving objects. */
struct scope_cache {
  bool used;
  char cache_path[CACHE_PATH_BUF];
  char requester_path[PATH_BUF];
  char ld_library_path[PATH_BUF];
  const char *file_data; /* mmap'd; NULL for an empty file */
  size_t file_len;
  struct lnx_stat file_stat;
  uint64_t last_used;
};

struct dynamic_info {
  const char *strtab;
  size_t strtab_size;
  const char *soname;
  const char *runpath;
  bool has_rpath;
  bool has_runpath;
};

struct sbuf {
  char *data;
  size_t cap;
  size_t len;
  bool ok;
};

static int state_lock;
static struct scope_cache scope_caches[SCOPE_CACHE_CAP];
static uint64_t scope_cache_tick;

/* -ffreestanding still lets the compiler emit calls to these four for struct
 * copies and zeroing, so they need real definitions with external linkage.
 * The module has no DT_NEEDED and links with -Bsymbolic, so they always bind
 * locally within the audit namespace. */
void *
memcpy(void *dst, const void *src, size_t n)
{
  char *d = dst;
  const char *s = src;
  for (size_t i = 0; i < n; ++i) {
    d[i] = s[i];
  }
  return dst;
}

void *
memmove(void *dst, const void *src, size_t n)
{
  char *d = dst;
  const char *s = src;
  if (d < s) {
    for (size_t i = 0; i < n; ++i) {
      d[i] = s[i];
    }
  } else {
    for (size_t i = n; i > 0; --i) {
      d[i - 1] = s[i - 1];
    }
  }
  return dst;
}

void *
memset(void *dst, int value, size_t n)
{
  char *d = dst;
  for (size_t i = 0; i < n; ++i) {
    d[i] = (char) value;
  }
  return dst;
}

int
memcmp(const void *left, const void *right, size_t n)
{
  const unsigned char *l = left;
  const unsigned char *r = right;
  for (size_t i = 0; i < n; ++i) {
    if (l[i] != r[i]) {
      return l[i] < r[i] ? -1 : 1;
    }
  }
  return 0;
}

static size_t
xstrlen(const char *s)
{
  const char *p = s;
  while (*p != '\0') {
    ++p;
  }
  return (size_t) (p - s);
}

static int
xstrcmp(const char *left, const char *right)
{
  while (*left != '\0' && *left == *right) {
    ++left;
    ++right;
  }
  return (unsigned char) *left - (unsigned char) *right;
}

static const char *
xstrchr(const char *s, char c)
{
  for (; *s != '\0'; ++s) {
    if (*s == c) {
      return s;
    }
  }
  return NULL;
}

static const char *
xstrchrnul(const char *s, char c)
{
  for (; *s != '\0'; ++s) {
    if (*s == c) {
      return s;
    }
  }
  return s;
}

static const char *
xmemchr(const char *s, char c, size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    if (s[i] == c) {
      return s + i;
    }
  }
  return NULL;
}

static bool
starts_with(const char *value, const char *prefix)
{
  while (*prefix != '\0') {
    if (*value++ != *prefix++) {
      return false;
    }
  }
  return true;
}

static bool
copy_str_bounded(char *dst, size_t cap, const char *src)
{
  size_t len = xstrlen(src);
  if (len >= cap) {
    return false;
  }
  memcpy(dst, src, len + 1);
  return true;
}

/* Bounded string builder. Overflow truncates and clears ok; callers building
 * paths must check ok before using the result. */
static void
sbuf_init(struct sbuf *b, char *data, size_t cap)
{
  b->data = data;
  b->cap = cap;
  b->len = 0;
  b->ok = cap > 0;
  if (cap > 0) {
    data[0] = '\0';
  }
}

static void
sbuf_putn(struct sbuf *b, const char *s, size_t n)
{
  if (b->cap == 0) {
    b->ok = false;
    return;
  }
  size_t space = b->cap - b->len - 1;
  if (n > space) {
    n = space;
    b->ok = false;
  }
  memcpy(b->data + b->len, s, n);
  b->len += n;
  b->data[b->len] = '\0';
}

static void
sbuf_puts(struct sbuf *b, const char *s)
{
  sbuf_putn(b, s, xstrlen(s));
}

static void
sbuf_put_hex16(struct sbuf *b, uint64_t value)
{
  char tmp[16];
  for (int i = 15; i >= 0; --i) {
    tmp[i] = "0123456789abcdef"[value & 0xf];
    value >>= 4;
  }
  sbuf_putn(b, tmp, sizeof(tmp));
}

static void
sbuf_put_dec(struct sbuf *b, uint64_t value)
{
  char tmp[20];
  size_t i = sizeof(tmp);
  do {
    tmp[--i] = (char) ('0' + (value % 10));
    value /= 10;
  } while (value != 0);
  sbuf_putn(b, tmp + i, sizeof(tmp) - i);
}

/* Three-state futex mutex (0 free, 1 locked, 2 contended). */
static int
atomic_cmpxchg(int *ptr, int expected, int desired)
{
  __atomic_compare_exchange_n(ptr, &expected, desired, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
  return expected;
}

static void
mutex_lock(int *lock)
{
  int c = atomic_cmpxchg(lock, 0, 1);
  if (c == 0) {
    return;
  }
  if (c != 2) {
    c = __atomic_exchange_n(lock, 2, __ATOMIC_ACQ_REL);
  }
  while (c != 0) {
    lnx_futex(lock, LNX_FUTEX_WAIT | LNX_FUTEX_PRIVATE_FLAG, 2, NULL);
    c = __atomic_exchange_n(lock, 2, __ATOMIC_ACQ_REL);
  }
}

static void
mutex_unlock(int *lock)
{
  if (__atomic_exchange_n(lock, 0, __ATOMIC_ACQ_REL) == 2) {
    lnx_futex(lock, LNX_FUTEX_WAKE | LNX_FUTEX_PRIVATE_FLAG, 1, NULL);
  }
}

/* Bump allocator for the strings handed to glibc on cache hits. glibc never
 * frees an la_objsearch result, so nothing here needs (or has) a free path. */
static char *arena_next;
static size_t arena_left;

static char *
arena_alloc(size_t n)
{
  if (n > arena_left) {
    size_t chunk = ARENA_CHUNK;
    if (n > chunk) {
      chunk = (n + (ARENA_CHUNK - 1)) & ~((size_t) ARENA_CHUNK - 1);
    }
    char *mapped = lnx_mmap(NULL, chunk, LNX_PROT_READ | LNX_PROT_WRITE,
                            LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS, -1, 0);
    if (mapped == NULL) {
      return NULL;
    }
    arena_next = mapped;
    arena_left = chunk;
  }
  char *out = arena_next;
  arena_next += n;
  arena_left -= n;
  return out;
}

static char *
arena_strdup(const char *value)
{
  size_t len = xstrlen(value) + 1;
  char *copy = arena_alloc(len);
  if (copy != NULL) {
    memcpy(copy, value, len);
  }
  return copy;
}

/* Environment snapshot. There is no libc environ to consult, so the initial
 * environment is read once from /proc/self/environ. That matches loader
 * semantics: glibc itself snapshots LD_LIBRARY_PATH and friends at startup,
 * so later setenv() calls never influence resolution anyway. */
static char *env_data;
static size_t env_len;
static int env_once; /* 0 not loaded, 1 loading, 2 loaded */

static void
env_load(void)
{
  char *buf = lnx_mmap(NULL, ENV_MAP_SIZE, LNX_PROT_READ | LNX_PROT_WRITE,
                       LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS, -1, 0);
  if (buf == NULL) {
    return;
  }

  long fd = lnx_openat(LNX_AT_FDCWD, "/proc/self/environ", LNX_O_RDONLY | LNX_O_CLOEXEC, 0);
  if (fd < 0) {
    lnx_munmap(buf, ENV_MAP_SIZE);
    return;
  }

  size_t len = 0;
  while (len < ENV_MAP_SIZE) {
    long rc = lnx_read(fd, buf + len, ENV_MAP_SIZE - len);
    if (rc == -LNX_EINTR) {
      continue;
    }
    if (rc < 0) {
      lnx_close(fd);
      lnx_munmap(buf, ENV_MAP_SIZE);
      return;
    }
    if (rc == 0) {
      break;
    }
    len += (size_t) rc;
  }
  lnx_close(fd);

  /* A full buffer means possible truncation; a half-parsed environment could
   * misread LD_LIBRARY_PATH, so treat it as unavailable (module goes inert). */
  if (len == ENV_MAP_SIZE) {
    lnx_munmap(buf, ENV_MAP_SIZE);
    return;
  }

  env_data = buf;
  env_len = len;
}

static void
env_ensure(void)
{
  if (__atomic_load_n(&env_once, __ATOMIC_ACQUIRE) == 2) {
    return;
  }
  if (atomic_cmpxchg(&env_once, 0, 1) == 0) {
    env_load();
    __atomic_store_n(&env_once, 2, __ATOMIC_RELEASE);
    lnx_futex(&env_once, LNX_FUTEX_WAKE | LNX_FUTEX_PRIVATE_FLAG, 0x7fffffff, NULL);
    return;
  }
  while (__atomic_load_n(&env_once, __ATOMIC_ACQUIRE) != 2) {
    lnx_futex(&env_once, LNX_FUTEX_WAIT | LNX_FUTEX_PRIVATE_FLAG, 1, NULL);
  }
}

/* getenv over the snapshot: returns the NUL-terminated value or NULL. */
static const char *
env_get(const char *name)
{
  if (env_data == NULL) {
    return NULL;
  }

  size_t name_len = xstrlen(name);
  const char *p = env_data;
  const char *end = env_data + env_len;

  while (p < end) {
    const char *entry_end = xmemchr(p, '\0', (size_t) (end - p));
    if (entry_end == NULL) {
      break; /* unterminated tail; never valid in /proc/self/environ */
    }
    if ((size_t) (entry_end - p) > name_len
        && p[name_len] == '='
        && memcmp(p, name, name_len) == 0) {
      return p + name_len + 1;
    }
    p = entry_end + 1;
  }

  return NULL;
}

/* Unused when both debug logging and daemonless mode are compiled out. */
__attribute__((unused)) static long
write_full(long fd, const void *buf, size_t len)
{
  const char *p = buf;
  size_t offset = 0;

  while (offset < len) {
    long rc = lnx_write(fd, p + offset, len - offset);
    if (rc == -LNX_EINTR) {
      continue;
    }
    if (rc <= 0) {
      return -1;
    }
    offset += (size_t) rc;
  }

  return 0;
}

#if NIX_LD_AUDIT_ENABLE_DEBUG
static int debug_lock;
static bool debug_logging;
static bool debug_logging_resolved;
static char debug_buf[16384];

/* Resolved once: la_objsearch runs on the startup path this module exists to
 * speed up, so an env scan per log call is measurable overhead. */
static bool
debug_enabled(void)
{
  if (!debug_logging_resolved) {
    env_ensure();
    const char *value = env_get("NIX_LD_AUDIT_DEBUG");
    debug_logging = value != NULL && value[0] != '\0' && xstrcmp(value, "0") != 0;
    debug_logging_resolved = true;
  }

  return debug_logging;
}
#endif

/* Supports %s (and %%) only — every message here is string-valued. Formats
 * into a static buffer under its own lock and writes fd 2 in one call so
 * concurrent threads do not interleave partial lines. */
static void
debugf(const char *fmt, ...)
{
#if NIX_LD_AUDIT_ENABLE_DEBUG
  if (!debug_enabled()) {
    return;
  }

  va_list ap;
  va_start(ap, fmt);
  mutex_lock(&debug_lock);

  struct sbuf b;
  sbuf_init(&b, debug_buf, sizeof(debug_buf));
  sbuf_puts(&b, "nix-ld-cache-audit: ");
  for (const char *p = fmt; *p != '\0'; ++p) {
    if (p[0] == '%' && p[1] == 's') {
      const char *arg = va_arg(ap, const char *);
      sbuf_puts(&b, arg != NULL ? arg : "(null)");
      ++p;
    } else if (p[0] == '%' && p[1] == '%') {
      sbuf_putn(&b, "%", 1);
      ++p;
    } else {
      sbuf_putn(&b, p, 1);
    }
  }
  sbuf_putn(&b, "\n", 1);
  write_full(2, b.data, b.len);

  mutex_unlock(&debug_lock);
  va_end(ap);
#else
  (void) fmt;
#endif
}

static uint64_t
fnv1a64_update(uint64_t hash, const char *value)
{
  for (const unsigned char *p = (const unsigned char *) value; *p != '\0'; ++p) {
    hash ^= *p;
    hash *= 1099511628211ULL;
  }

  return hash;
}

static bool
path_is_absolute(const char *path)
{
  return path != NULL && path[0] == '/';
}

static bool
span_is_safe_store_path(const char *path, size_t len)
{
  if (len < sizeof(STORE_PREFIX) - 1 || memcmp(path, STORE_PREFIX, sizeof(STORE_PREFIX) - 1) != 0) {
    return false;
  }

  if (xmemchr(path, '\n', len) != NULL || xmemchr(path, '\t', len) != NULL) {
    return false;
  }

  const char *p = path;
  const char *end = path + len;
  while (p < end) {
    while (p < end && *p == '/') {
      ++p;
    }
    if (p == end) {
      break;
    }

    const char *component_end = p;
    while (component_end < end && *component_end != '/') {
      ++component_end;
    }
    size_t component_len = (size_t) (component_end - p);
    if ((component_len == 1 && p[0] == '.')
        || (component_len == 2 && p[0] == '.' && p[1] == '.')) {
      return false;
    }
    p = component_end;
  }

  return true;
}

static bool
path_is_safe_store_path(const char *path)
{
  return path != NULL && span_is_safe_store_path(path, xstrlen(path));
}

/* Mirrors search_path_is_cacheable() in the daemon: only immutable, token-free
 * store directories keep a cached resolution valid. */
static bool
search_path_is_cacheable(const char *search_path)
{
  if (search_path == NULL || search_path[0] == '\0') {
    return false;
  }

  const char *entry = search_path;
  while (true) {
    const char *end = xstrchrnul(entry, ':');
    size_t len = (size_t) (end - entry);

    if (len == 0) {
      return false;
    }
    if (xmemchr(entry, '$', len) != NULL || !span_is_safe_store_path(entry, len)) {
      return false;
    }

    if (*end == '\0') {
      break;
    }
    entry = end + 1;
  }

  return true;
}

static bool
environment_is_cacheable(void)
{
  const char *ld_library_path = env_get("LD_LIBRARY_PATH");
  if (ld_library_path == NULL || ld_library_path[0] == '\0') {
    return true;
  }

  /* The submit protocol caps fields at NIX_LD_CACHE_PROTOCOL_MAX_FIELD, so no
   * scope with a longer LD_LIBRARY_PATH can ever have been learned; skipping
   * it here keeps every later buffer bounded. */
  if (xstrlen(ld_library_path) >= PATH_BUF) {
    return false;
  }

  return search_path_is_cacheable(ld_library_path);
}

/* realpath() for existing files without libc: hold an O_PATH fd and read the
 * kernel's canonical answer from /proc/self/fd. */
static bool
resolve_realpath(const char *path, char out[PATH_BUF])
{
  long fd = lnx_openat(LNX_AT_FDCWD, path, LNX_O_PATH | LNX_O_CLOEXEC, 0);
  if (fd < 0) {
    return false;
  }

  char link_path[48];
  struct sbuf b;
  sbuf_init(&b, link_path, sizeof(link_path));
  sbuf_puts(&b, "/proc/self/fd/");
  sbuf_put_dec(&b, (uint64_t) fd);

  long len = -1;
  if (b.ok) {
    len = lnx_readlinkat(LNX_AT_FDCWD, link_path, out, PATH_BUF - 1);
  }
  lnx_close(fd);

  if (len <= 0 || len >= PATH_BUF - 1) {
    return false;
  }
  out[len] = '\0';
  return out[0] == '/';
}

/* Requesters under /run are keyed by their store target so one symlinked
 * library does not fragment the cache per activation. */
static bool
requester_identity(uintptr_t cookie_value, char out[PATH_BUF])
{
  const struct lnx_link_map *map = (const struct lnx_link_map *) cookie_value;

  /* The main executable's l_name is empty, so fall back to /proc/self/exe. */
  if (map != NULL && map->l_name != NULL && map->l_name[0] != '\0') {
    if (starts_with(map->l_name, RUN_PREFIX)) {
      char resolved[PATH_BUF];
      if (resolve_realpath(map->l_name, resolved) && path_is_safe_store_path(resolved)) {
        return copy_str_bounded(out, PATH_BUF, resolved);
      }
    }
    return copy_str_bounded(out, PATH_BUF, map->l_name);
  }

  long len = lnx_readlinkat(LNX_AT_FDCWD, "/proc/self/exe", out, PATH_BUF - 1);
  if (len <= 0 || len >= PATH_BUF - 1) {
    return false;
  }
  out[len] = '\0';
  return true;
}

static bool
parse_mapped_dynamic_info(uintptr_t cookie_value, struct dynamic_info *info)
{
  memset(info, 0, sizeof(*info));

  const struct lnx_link_map *map = (const struct lnx_link_map *) cookie_value;
  if (map == NULL || map->l_ld == NULL) {
    return false;
  }

  uint64_t runpath_off = 0;

  for (const struct lnx_elf64_dyn *dyn = map->l_ld; dyn->d_tag != LNX_DT_NULL; ++dyn) {
    switch (dyn->d_tag) {
      case LNX_DT_STRTAB:
        /* glibc relocates DT_STRTAB in place, so d_un is an absolute pointer. */
        info->strtab = (const char *) (uintptr_t) dyn->d_un;
        break;
      case LNX_DT_STRSZ:
        info->strtab_size = (size_t) dyn->d_un;
        break;
      case LNX_DT_RUNPATH:
        runpath_off = dyn->d_un;
        info->has_runpath = true;
        break;
      case LNX_DT_RPATH:
        info->has_rpath = true;
        break;
      default:
        break;
    }
  }

  if (info->strtab == NULL || info->strtab_size == 0 || (uintptr_t) info->strtab < 0x1000) {
    return false;
  }

  if (info->strtab[info->strtab_size - 1] != '\0') {
    return false;
  }

  if (info->has_runpath) {
    if (runpath_off >= info->strtab_size) {
      return false;
    }
    info->runpath = info->strtab + runpath_off;
  }

  return true;
}

/* Mirrors the daemon's predicate: DT_RUNPATH must be present (which suppresses
 * the DT_RPATH chain in glibc), DT_RPATH must be absent, and every RUNPATH
 * entry must be a token-free store path. Anything else is not cacheable. */
static bool
requester_runpath_cacheable(uintptr_t cookie_value)
{
  struct dynamic_info info;
  if (!parse_mapped_dynamic_info(cookie_value, &info)) {
    return false;
  }

  return info.has_runpath && !info.has_rpath && search_path_is_cacheable(info.runpath);
}

static bool
cache_dir(struct sbuf *b)
{
  const char *root = env_get("NIX_LD_AUDIT_CACHE_DIR");
  if (root != NULL && root[0] != '\0') {
    sbuf_puts(b, root);
    return b->ok;
  }

  root = env_get("XDG_CACHE_HOME");
  if (root != NULL && root[0] != '\0') {
    sbuf_puts(b, root);
    sbuf_puts(b, "/nix-ld-cache");
    return b->ok;
  }

  root = env_get("HOME");
  if (root != NULL && root[0] != '\0') {
    sbuf_puts(b, root);
    sbuf_puts(b, "/.cache/nix-ld-cache");
    return b->ok;
  }

  sbuf_puts(b, "/var/tmp/nix-ld-cache-audit-");
  sbuf_put_dec(b, (uint64_t) lnx_getuid());
  return b->ok;
}

/* Streams the scope key through FNV-1a instead of materializing it. The bytes
 * hashed here must stay identical to cache_scope_key() in nix-ld-cache-daemon.c
 * ("v2\nrequester=%s\nld_library_path=%s\n"); any drift silently reads a scope
 * the daemon never writes. */
static bool
cache_file_path(char out[CACHE_PATH_BUF], const char *requester_path, const char *ld_library_path)
{
  struct sbuf b;
  sbuf_init(&b, out, CACHE_PATH_BUF);
  if (!cache_dir(&b)) {
    return false;
  }

  uint64_t hash = 14695981039346656037ULL;
  hash = fnv1a64_update(hash, "v2\nrequester=");
  hash = fnv1a64_update(hash, requester_path);
  hash = fnv1a64_update(hash, "\nld_library_path=");
  hash = fnv1a64_update(hash, ld_library_path != NULL ? ld_library_path : "");
  hash = fnv1a64_update(hash, "\n");

  sbuf_puts(&b, "/");
  sbuf_put_hex16(&b, hash);
  sbuf_puts(&b, ".tsv");
  return b.ok;
}

static bool
file_exists_readable(const char *path)
{
  return path_is_absolute(path) && lnx_faccessat(LNX_AT_FDCWD, path, LNX_R_OK) == 0;
}

static bool
map_file(const char *path, const char **data_out, size_t *len_out, struct lnx_stat *stat_out)
{
  long fd = lnx_openat(LNX_AT_FDCWD, path, LNX_O_RDONLY | LNX_O_CLOEXEC, 0);
  if (fd < 0) {
    return false;
  }

  struct lnx_stat st;
  if (lnx_fstat(fd, &st) != 0 || !LNX_S_ISREG(st.st_mode)) {
    lnx_close(fd);
    return false;
  }

  const char *data = NULL;
  size_t len = (size_t) st.st_size;
  if (len > 0) {
    void *mapped = lnx_mmap(NULL, len, LNX_PROT_READ, LNX_MAP_PRIVATE, fd, 0);
    if (mapped == NULL) {
      lnx_close(fd);
      return false;
    }
    data = mapped;
  }

  lnx_close(fd);
  *data_out = data;
  *len_out = len;
  if (stat_out != NULL) {
    *stat_out = st;
  }
  return true;
}

static void
unmap_file(const char *data, size_t len)
{
  if (data != NULL) {
    lnx_munmap((void *) data, len);
  }
}

static void
scope_cache_reset(struct scope_cache *cache)
{
  unmap_file(cache->file_data, cache->file_len);
  memset(cache, 0, sizeof(*cache));
}

static bool
stat_matches(const struct lnx_stat *left, const struct lnx_stat *right)
{
  return left->st_dev == right->st_dev
    && left->st_ino == right->st_ino
    && left->st_size == right->st_size
    && left->st_mtime_sec == right->st_mtime_sec
    && left->st_mtime_nsec == right->st_mtime_nsec
    && left->st_ctime_sec == right->st_ctime_sec
    && left->st_ctime_nsec == right->st_ctime_nsec;
}

static bool
scope_cache_current(const struct scope_cache *cache)
{
  struct lnx_stat st;
  return cache->used
    && lnx_newfstatat(LNX_AT_FDCWD, cache->cache_path, &st, 0) == 0
    && LNX_S_ISREG(st.st_mode)
    && stat_matches(&cache->file_stat, &st);
}

static struct scope_cache *
scope_cache_find(const char *requester_path, const char *ld_library_path)
{
  for (size_t i = 0; i < SCOPE_CACHE_CAP; ++i) {
    struct scope_cache *cache = &scope_caches[i];
    if (cache->used
        && xstrcmp(cache->requester_path, requester_path) == 0
        && xstrcmp(cache->ld_library_path, ld_library_path) == 0) {
      cache->last_used = ++scope_cache_tick;
      return cache;
    }
  }

  return NULL;
}

static struct scope_cache *
scope_cache_victim(void)
{
  struct scope_cache *victim = &scope_caches[0];

  for (size_t i = 0; i < SCOPE_CACHE_CAP; ++i) {
    struct scope_cache *cache = &scope_caches[i];
    if (!cache->used) {
      return cache;
    }
    if (cache->last_used < victim->last_used) {
      victim = cache;
    }
  }

  return victim;
}

/* Loads and memoizes the scope's cache file. Missing files are not memoized:
 * the daemon may create them after an earlier miss in the same process. */
static struct scope_cache *
scope_cache_load(const char *requester_path)
{
  const char *ld_library_path = env_get("LD_LIBRARY_PATH");
  if (ld_library_path == NULL) {
    ld_library_path = "";
  }

  struct scope_cache *cache = scope_cache_find(requester_path, ld_library_path);
  if (cache != NULL) {
    return cache;
  }

  char cache_path[CACHE_PATH_BUF];
  if (!cache_file_path(cache_path, requester_path, ld_library_path)) {
    return NULL;
  }

  const char *data;
  size_t len;
  struct lnx_stat st;
  if (!map_file(cache_path, &data, &len, &st)) {
    return NULL;
  }

  cache = scope_cache_victim();
  scope_cache_reset(cache);

  if (!copy_str_bounded(cache->cache_path, sizeof(cache->cache_path), cache_path)
      || !copy_str_bounded(cache->requester_path, sizeof(cache->requester_path), requester_path)
      || !copy_str_bounded(cache->ld_library_path, sizeof(cache->ld_library_path), ld_library_path)) {
    unmap_file(data, len);
    scope_cache_reset(cache);
    return NULL;
  }

  cache->used = true;
  cache->file_data = data;
  cache->file_len = len;
  cache->file_stat = st;
  cache->last_used = ++scope_cache_tick;
  return cache;
}

/* Finds the first line whose soname column matches and copies its path column
 * into out. Lines are "<soname>\t<path>\n". */
static bool
tsv_find(const char *buf, size_t len, const char *soname, char out[PATH_BUF])
{
  const char *p = buf;
  const char *end = buf + len;
  size_t soname_len = xstrlen(soname);

  while (p < end) {
    const char *newline = xmemchr(p, '\n', (size_t) (end - p));
    const char *line_end = newline != NULL ? newline : end;

    const char *tab = xmemchr(p, '\t', (size_t) (line_end - p));
    if (tab != NULL
        && (size_t) (tab - p) == soname_len
        && memcmp(p, soname, soname_len) == 0) {
      size_t value_len = (size_t) (line_end - tab - 1);
      if (value_len >= PATH_BUF) {
        return false;
      }
      memcpy(out, tab + 1, value_len);
      out[value_len] = '\0';
      return true;
    }

    if (newline == NULL) {
      break;
    }
    p = newline + 1;
  }

  return false;
}

/* Scans the memoized scope for soname. Caller holds state_lock. */
static bool
scan_scope_cache(const struct scope_cache *cache, const char *soname, char out[PATH_BUF])
{
  return tsv_find(cache->file_data, cache->file_len, soname, out)
    && file_exists_readable(out);
}

/* The daemon appends to scope files asynchronously, so a loaded scope can become
 * stale after a miss. Retry once with a fresh read before falling back to glibc. */
static bool
lookup_cache_entry(const char *requester_path, const char *soname, char out[PATH_BUF])
{
  struct scope_cache *cache = scope_cache_load(requester_path);
  if (cache == NULL) {
    return false;
  }

  if (scan_scope_cache(cache, soname, out)) {
    return true;
  }

  if (scope_cache_current(cache)) {
    return false;
  }

  scope_cache_reset(cache);
  cache = scope_cache_load(requester_path);
  if (cache == NULL) {
    return false;
  }

  return scan_scope_cache(cache, soname, out);
}

#if NIX_LD_AUDIT_ENABLE_DAEMONLESS
struct elf_image {
  const char *data;
  size_t size;
};

static const char *
xstrrchr(const char *s, char c)
{
  const char *last = NULL;
  for (; *s != '\0'; ++s) {
    if (*s == c) {
      last = s;
    }
  }
  return last;
}

static bool
field_is_safe_soname(const char *soname)
{
  return soname != NULL
    && soname[0] != '\0'
    && xstrchr(soname, '/') == NULL
    && xstrchr(soname, '\n') == NULL
    && xstrchr(soname, '\t') == NULL;
}

static bool
tsv_contains(const char *buf, size_t len, const char *soname, const char *path)
{
  const char *p = buf;
  const char *end = buf + len;
  size_t soname_len = xstrlen(soname);
  size_t path_len = xstrlen(path);

  while (p < end) {
    const char *newline = xmemchr(p, '\n', (size_t) (end - p));
    const char *line_end = newline != NULL ? newline : end;
    const char *tab = xmemchr(p, '\t', (size_t) (line_end - p));

    if (tab != NULL
        && (size_t) (tab - p) == soname_len
        && (size_t) (line_end - tab - 1) == path_len
        && memcmp(p, soname, soname_len) == 0
        && memcmp(tab + 1, path, path_len) == 0) {
      return true;
    }

    if (newline == NULL) {
      break;
    }
    p = newline + 1;
  }

  return false;
}

static long
mkdir_p(const char *path)
{
  char copy[CACHE_PATH_BUF];
  if (!copy_str_bounded(copy, sizeof(copy), path)) {
    return -1;
  }

  for (char *p = copy + 1; *p != '\0'; ++p) {
    if (*p != '/') {
      continue;
    }

    *p = '\0';
    long rc = lnx_mkdirat(LNX_AT_FDCWD, copy, 0755);
    if (rc != 0 && rc != -LNX_EEXIST) {
      return -1;
    }
    *p = '/';
  }

  long rc = lnx_mkdirat(LNX_AT_FDCWD, copy, 0755);
  return (rc == 0 || rc == -LNX_EEXIST) ? 0 : -1;
}

static void
unload_elf_image(struct elf_image *image)
{
  unmap_file(image->data, image->size);
  image->data = NULL;
  image->size = 0;
}

static bool
load_elf_image(const char *path, struct elf_image *image)
{
  memset(image, 0, sizeof(*image));

  char resolved[PATH_BUF];
  if (!resolve_realpath(path, resolved) || !path_is_safe_store_path(resolved)) {
    return false;
  }

  const char *data;
  size_t len;
  if (!map_file(path, &data, &len, NULL)) {
    return false;
  }
  if (len < sizeof(struct lnx_elf64_ehdr)) {
    unmap_file(data, len);
    return false;
  }

  image->data = data;
  image->size = len;
  return true;
}

static bool
elf_bounds_ok(const struct elf_image *image, size_t off, size_t size)
{
  return off <= image->size && size <= image->size - off;
}

static bool
vaddr_to_offset(const struct elf_image *image, const struct lnx_elf64_phdr *phdrs, size_t phnum,
                uint64_t vaddr, size_t *offset_out)
{
  for (size_t i = 0; i < phnum; ++i) {
    const struct lnx_elf64_phdr *ph = &phdrs[i];
    if (ph->p_type != LNX_PT_LOAD) {
      continue;
    }
    if (vaddr < ph->p_vaddr || vaddr >= ph->p_vaddr + ph->p_memsz) {
      continue;
    }

    size_t delta = (size_t) (vaddr - ph->p_vaddr);
    if (delta > ph->p_filesz || ph->p_offset > SIZE_MAX - delta) {
      return false;
    }
    if (!elf_bounds_ok(image, (size_t) ph->p_offset + delta, 1)) {
      return false;
    }
    *offset_out = (size_t) ph->p_offset + delta;
    return true;
  }

  return false;
}

static bool
parse_file_dynamic_info(const struct elf_image *image, struct dynamic_info *info)
{
  memset(info, 0, sizeof(*info));

  if (!elf_bounds_ok(image, 0, sizeof(struct lnx_elf64_ehdr))) {
    return false;
  }

  const struct lnx_elf64_ehdr *ehdr = (const struct lnx_elf64_ehdr *) image->data;
  if (memcmp(ehdr->e_ident, "\177ELF", 4) != 0
      || ehdr->e_ident[LNX_EI_CLASS] != LNX_ELFCLASS64
      || ehdr->e_ident[LNX_EI_DATA] != LNX_ELFDATA2LSB) {
    return false;
  }

  if (!elf_bounds_ok(image, ehdr->e_phoff, (size_t) ehdr->e_phnum * sizeof(struct lnx_elf64_phdr))) {
    return false;
  }

  const struct lnx_elf64_phdr *phdrs =
    (const struct lnx_elf64_phdr *) (image->data + ehdr->e_phoff);
  const struct lnx_elf64_dyn *dynamic = NULL;
  size_t dynamic_count = 0;

  for (size_t i = 0; i < ehdr->e_phnum; ++i) {
    if (phdrs[i].p_type != LNX_PT_DYNAMIC) {
      continue;
    }
    if (!elf_bounds_ok(image, phdrs[i].p_offset, phdrs[i].p_filesz)) {
      return false;
    }
    dynamic = (const struct lnx_elf64_dyn *) (image->data + phdrs[i].p_offset);
    dynamic_count = phdrs[i].p_filesz / sizeof(struct lnx_elf64_dyn);
    break;
  }

  if (dynamic == NULL) {
    return false;
  }

  uint64_t strtab_vaddr = 0;
  uint64_t soname_off = 0;
  bool have_soname = false;

  for (size_t i = 0; i < dynamic_count && dynamic[i].d_tag != LNX_DT_NULL; ++i) {
    switch (dynamic[i].d_tag) {
      case LNX_DT_STRTAB:
        strtab_vaddr = dynamic[i].d_un;
        break;
      case LNX_DT_STRSZ:
        info->strtab_size = (size_t) dynamic[i].d_un;
        break;
      case LNX_DT_SONAME:
        soname_off = dynamic[i].d_un;
        have_soname = true;
        break;
      default:
        break;
    }
  }

  size_t strtab_off = 0;
  if (strtab_vaddr == 0 || !vaddr_to_offset(image, phdrs, ehdr->e_phnum, strtab_vaddr, &strtab_off)) {
    return false;
  }

  if (info->strtab_size == 0 || !elf_bounds_ok(image, strtab_off, info->strtab_size)) {
    return false;
  }

  info->strtab = image->data + strtab_off;
  if (info->strtab[info->strtab_size - 1] != '\0') {
    return false;
  }

  if (have_soname && soname_off < info->strtab_size) {
    info->soname = info->strtab + soname_off;
  }

  return true;
}

static bool
soname_matches(const char *path, const char *soname)
{
  struct elf_image image;
  if (!load_elf_image(path, &image)) {
    return false;
  }

  struct dynamic_info info;
  bool match = false;
  if (parse_file_dynamic_info(&image, &info)) {
    if (info.soname != NULL) {
      match = xstrcmp(info.soname, soname) == 0;
    } else {
      const char *base = xstrrchr(path, '/');
      match = xstrcmp(base != NULL ? base + 1 : path, soname) == 0;
    }
  }

  unload_elf_image(&image);
  return match;
}

static bool
candidate_is_safe_store_file(const char *candidate)
{
  struct lnx_stat st;
  if (lnx_newfstatat(LNX_AT_FDCWD, candidate, &st, 0) != 0 || !LNX_S_ISREG(st.st_mode)) {
    return false;
  }

  char resolved[PATH_BUF];
  return resolve_realpath(candidate, resolved) && path_is_safe_store_path(resolved);
}

static bool
first_hit_in_search_path(const char *search_path, const char *soname, char out[PATH_BUF])
{
  if (search_path == NULL) {
    return false;
  }

  const char *entry = search_path;
  while (true) {
    const char *end = xstrchrnul(entry, ':');
    size_t len = (size_t) (end - entry);

    if (len > 0) {
      struct sbuf b;
      sbuf_init(&b, out, PATH_BUF);
      sbuf_putn(&b, entry, len);
      sbuf_puts(&b, "/");
      sbuf_puts(&b, soname);
      if (b.ok && candidate_is_safe_store_file(out)) {
        return true;
      }
    }

    if (*end == '\0') {
      break;
    }
    entry = end + 1;
  }

  return false;
}

static bool
derive_resolution(uintptr_t cookie_value, const char *requester_path, const char *soname,
                  char out[PATH_BUF])
{
  if (!path_is_safe_store_path(requester_path) || !field_is_safe_soname(soname)) {
    debugf("daemonless reject reason=invalid-fields requester=%s soname=%s",
           requester_path, soname);
    return false;
  }

  struct dynamic_info info;
  if (!parse_mapped_dynamic_info(cookie_value, &info)) {
    debugf("daemonless reject reason=unparsable-requester requester=%s soname=%s",
           requester_path, soname);
    return false;
  }

  if (!info.has_runpath) {
    debugf("daemonless reject reason=no-runpath requester=%s soname=%s", requester_path, soname);
    return false;
  }

  if (info.has_rpath) {
    debugf("daemonless reject reason=rpath-present requester=%s soname=%s", requester_path, soname);
    return false;
  }

  if (!search_path_is_cacheable(info.runpath)) {
    debugf("daemonless reject reason=unsafe-runpath requester=%s soname=%s", requester_path, soname);
    return false;
  }

  const char *ld_library_path = env_get("LD_LIBRARY_PATH");
  bool hit = false;

  if (ld_library_path != NULL && ld_library_path[0] != '\0') {
    if (!search_path_is_cacheable(ld_library_path)) {
      debugf("daemonless reject reason=unsafe-ld-library-path requester=%s soname=%s",
             requester_path, soname);
      return false;
    }
    hit = first_hit_in_search_path(ld_library_path, soname, out);
  }

  if (!hit) {
    hit = first_hit_in_search_path(info.runpath, soname, out);
  }

  if (!hit) {
    debugf("daemonless reject reason=no-hit-in-search-paths requester=%s soname=%s",
           requester_path, soname);
    return false;
  }

  if (!soname_matches(out, soname)) {
    debugf("daemonless reject reason=soname-mismatch requester=%s soname=%s path=%s",
           requester_path, soname, out);
    return false;
  }

  return true;
}

static bool
disk_cache_contains_line(const char *cache_path, const char *soname, const char *path)
{
  const char *data;
  size_t len;
  if (!map_file(cache_path, &data, &len, NULL)) {
    return false;
  }

  bool found = tsv_contains(data, len, soname, path);
  unmap_file(data, len);
  return found;
}

static long
commit_daemonless_cache_entry(const char *requester_path, const char *soname, const char *path)
{
  char dir[CACHE_PATH_BUF];
  struct sbuf db;
  sbuf_init(&db, dir, sizeof(dir));
  if (!cache_dir(&db) || mkdir_p(dir) != 0) {
    return -1;
  }

  const char *ld_library_path = env_get("LD_LIBRARY_PATH");
  if (ld_library_path == NULL) {
    ld_library_path = "";
  }

  char cache_path[CACHE_PATH_BUF];
  if (!cache_file_path(cache_path, requester_path, ld_library_path)) {
    return -1;
  }

  bool cache_proves_absent = false;
  mutex_lock(&state_lock);
  struct scope_cache *cache = scope_cache_find(requester_path, ld_library_path);
  if (cache != NULL && scope_cache_current(cache)) {
    if (tsv_contains(cache->file_data, cache->file_len, soname, path)) {
      mutex_unlock(&state_lock);
      return 0;
    }
    cache_proves_absent = true;
  }
  mutex_unlock(&state_lock);

  if (!cache_proves_absent && disk_cache_contains_line(cache_path, soname, path)) {
    return 0;
  }

  char line[PATH_BUF * 2 + 2];
  struct sbuf lb;
  sbuf_init(&lb, line, sizeof(line));
  sbuf_puts(&lb, soname);
  sbuf_putn(&lb, "\t", 1);
  sbuf_puts(&lb, path);
  sbuf_putn(&lb, "\n", 1);
  if (!lb.ok) {
    return -1;
  }

  long fd = lnx_openat(LNX_AT_FDCWD, cache_path,
                       LNX_O_WRONLY | LNX_O_CREAT | LNX_O_APPEND | LNX_O_CLOEXEC, 0664);
  if (fd < 0) {
    return -1;
  }

  /* One O_APPEND write keeps concurrent processes from tearing lines. */
  long rc = write_full(fd, lb.data, lb.len);
  lnx_close(fd);
  return rc;
}

static void
invalidate_scope_cache(const char *requester_path)
{
  mutex_lock(&state_lock);
  for (size_t i = 0; i < SCOPE_CACHE_CAP; ++i) {
    if (scope_caches[i].used
        && xstrcmp(scope_caches[i].requester_path, requester_path) == 0) {
      scope_cache_reset(&scope_caches[i]);
    }
  }
  mutex_unlock(&state_lock);
}

static bool
daemonless_enabled(void)
{
  const char *value = env_get("NIX_LD_AUDIT_DAEMONLESS");
  return value != NULL && value[0] != '\0' && xstrcmp(value, "0") != 0;
}

static long
submit_daemonless_cache_entry(uintptr_t cookie_value, const char *requester_path, const char *soname)
{
  char resolved[PATH_BUF];
  if (!derive_resolution(cookie_value, requester_path, soname, resolved)) {
    return 0;
  }

  debugf("daemonless commit requester=%s soname=%s path=%s", requester_path, soname, resolved);
  long rc = commit_daemonless_cache_entry(requester_path, soname, resolved);
  if (rc == 0) {
    invalidate_scope_cache(requester_path);
  }
  return rc;
}
#endif

/* MSG_NOSIGNAL keeps a daemon-side disconnect from raising SIGPIPE in the
 * audited process, which would kill an unrelated user program at startup. */
static long
send_full(long fd, const void *buf, size_t len)
{
  const char *p = buf;
  size_t offset = 0;

  while (offset < len) {
    long rc = lnx_sendto(fd, p + offset, len - offset, LNX_MSG_NOSIGNAL);
    if (rc == -LNX_EINTR) {
      continue;
    }
    if (rc <= 0) {
      return -1;
    }
    offset += (size_t) rc;
  }

  return 0;
}

/* Reports {requester, soname} and nothing else: the daemon derives the path
 * itself, so this cannot influence what gets cached. Daemonless mode mirrors
 * that derivation locally and writes only to the configured per-user cache. */
static long
submit_cache_entry(uintptr_t cookie_value, const char *requester_path, const char *soname)
{
#if NIX_LD_AUDIT_ENABLE_DAEMONLESS
  if (daemonless_enabled()) {
    return submit_daemonless_cache_entry(cookie_value, requester_path, soname);
  }
#else
  (void) cookie_value;
#endif

  const char *socket_path = env_get("NIX_LD_AUDIT_SOCKET");
  if (socket_path == NULL || socket_path[0] == '\0') {
    return 0;
  }

  const char *ld_library_path = env_get("LD_LIBRARY_PATH");
  if (ld_library_path == NULL) {
    ld_library_path = "";
  }

  size_t requester_len = xstrlen(requester_path);
  size_t soname_len = xstrlen(soname);
  size_t ld_library_path_len = xstrlen(ld_library_path);
  if (requester_len > NIX_LD_CACHE_PROTOCOL_MAX_FIELD
      || soname_len > NIX_LD_CACHE_PROTOCOL_MAX_FIELD
      || ld_library_path_len > NIX_LD_CACHE_PROTOCOL_MAX_FIELD) {
    return 0;
  }

  long fd = lnx_socket(LNX_AF_UNIX, LNX_SOCK_STREAM | LNX_SOCK_CLOEXEC | LNX_SOCK_NONBLOCK, 0);
  if (fd < 0) {
    return -1;
  }

  struct lnx_sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = LNX_AF_UNIX;
  if (!copy_str_bounded(addr.sun_path, sizeof(addr.sun_path), socket_path)) {
    lnx_close(fd);
    return -1;
  }

  /* Non-blocking connect bounded by ppoll(): a saturated daemon must not stall
   * process startup, and this runs on every cache miss. The socket stays
   * non-blocking for the sends too, so a full socket buffer drops the
   * submission instead of waiting. */
  long rc = lnx_connect(fd, &addr, sizeof(addr));
  if (rc != 0) {
    if (rc != -LNX_EINPROGRESS) {
      lnx_close(fd);
      return -1;
    }

    struct lnx_pollfd pfd = { .fd = (int) fd, .events = LNX_POLLOUT, .revents = 0 };
    struct lnx_timespec timeout = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
    rc = lnx_ppoll(&pfd, 1, &timeout);
    if (rc <= 0) {
      lnx_close(fd);
      return -1;
    }

    int err = 0;
    unsigned int errlen = sizeof(err);
    if (lnx_getsockopt(fd, LNX_SOL_SOCKET, LNX_SO_ERROR, &err, &errlen) != 0 || err != 0) {
      lnx_close(fd);
      return -1;
    }
  }

  struct nix_ld_cache_msg msg = {
    .magic = NIX_LD_CACHE_PROTOCOL_MAGIC,
    .version = NIX_LD_CACHE_PROTOCOL_VERSION,
    .requester_len = (uint32_t) requester_len,
    .soname_len = (uint32_t) soname_len,
    .ld_library_path_len = (uint32_t) ld_library_path_len,
  };

  rc = send_full(fd, &msg, sizeof(msg));
  rc = rc == 0 ? send_full(fd, requester_path, msg.requester_len) : rc;
  rc = rc == 0 ? send_full(fd, soname, msg.soname_len) : rc;
  rc = rc == 0 ? send_full(fd, ld_library_path, msg.ld_library_path_len) : rc;
  lnx_close(fd);
  return rc;
}

__attribute__((visibility("default"))) unsigned int
la_version(unsigned int version)
{
  /* Returning the caller's version keeps the module usable on an older glibc
   * rather than silently disabling itself. */
  return version < NIX_LAV_CURRENT ? version : NIX_LAV_CURRENT;
}

__attribute__((visibility("default"))) char *
la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
  if (name == NULL || cookie == NULL || flag != LNX_LA_SER_ORIG) {
    return (char *) name;
  }

  if (xstrchr(name, '/') != NULL) {
    return (char *) name;
  }

  env_ensure();

  if (!environment_is_cacheable()) {
    debugf("skip cache soname=%s reason=unsafe-ld-library-path", name);
    return (char *) name;
  }

  if (!requester_runpath_cacheable(*cookie)) {
    debugf("skip cache soname=%s reason=unsafe-runpath", name);
    return (char *) name;
  }

  char requester_path[PATH_BUF];
  if (!requester_identity(*cookie, requester_path)) {
    return (char *) name;
  }

  char path[PATH_BUF];
  char *cached = NULL;
  mutex_lock(&state_lock);
  if (lookup_cache_entry(requester_path, name, path)) {
    /* glibc never frees this; the arena leaks one allocation per distinct
     * soname per process and the audit ABI offers no hook to reclaim it. */
    cached = arena_strdup(path);
  }
  mutex_unlock(&state_lock);

  if (cached != NULL) {
    debugf("cache hit requester=%s soname=%s path=%s", requester_path, name, cached);
    return cached;
  }

  debugf("cache miss requester=%s soname=%s", requester_path, name);

  /* Submitted outside state_lock: this talks to the daemon, and blocking here
   * with the lock held would serialize every other thread's resolution. */
  submit_cache_entry(*cookie, requester_path, name);
  return (char *) name;
}
