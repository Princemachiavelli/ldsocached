#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "protocol.h"

#define MAX_CONNECTIONS 256
#define CONNECTION_TIMEOUT_MS 5000
#define STORE_PREFIX "/nix/store/"
#define WRITE_SCOPE_CACHE_CAP 64

/* Sentinel in epoll_event.data.u32, which otherwise carries a slot index. */
#define LISTEN_SLOT UINT32_MAX

static volatile sig_atomic_t stop_requested;
static bool debug_logging;

enum conn_state {
  CONN_READ_HEADER,
  CONN_READ_PAYLOAD,
};

struct connection {
  int fd;
  pid_t pid;
  enum conn_state state;
  uint64_t deadline_ms;
  struct nix_ld_cache_msg header;
  size_t header_got;
  char *payload;
  size_t payload_cap;
  size_t wire_len;
  size_t payload_got;
};

struct elf_image {
  void *data;
  size_t size;
};

struct dynamic_info {
  const char *strtab;
  size_t strtab_size;
  const char *soname;
  const char *runpath;
  bool has_rpath;
  bool has_runpath;
  const char **needed;
  size_t needed_count;
};

struct write_scope_cache {
  char *cache_path;
  char *file_contents;
  size_t file_len;
  uint64_t last_used;
  /* Identity of the file this snapshot was read from, so a change made by
   * anything other than this cache (an external `rm`, truncate, etc.) is
   * detected with a cheap stat() instead of trusted forever. */
  bool exists;
  dev_t dev;
  ino_t ino;
  off_t size;
  struct timespec mtim;
};

static struct write_scope_cache write_scope_caches[WRITE_SCOPE_CACHE_CAP];
static uint64_t write_scope_cache_tick;

static void
handle_signal(int signo)
{
  (void) signo;
  stop_requested = 1;
}

static bool path_is_safe_store_path(const char *path);

static void
debugf(const char *fmt, ...)
{
  if (!debug_logging) {
    return;
  }

  va_list ap;
  va_start(ap, fmt);
  flockfile(stderr);
  fputs("nix-ld-cache-daemon: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  funlockfile(stderr);
  va_end(ap);
}

static uint64_t
fnv1a64(const char *value)
{
  uint64_t hash = 14695981039346656037ULL;

  for (const unsigned char *p = (const unsigned char *) value; *p != '\0'; ++p) {
    hash ^= *p;
    hash *= 1099511628211ULL;
  }

  return hash;
}

static uint64_t
now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

static char *
xstrdup(const char *value)
{
  if (value == NULL) {
    return NULL;
  }

  size_t len = strlen(value) + 1;
  char *copy = malloc(len);
  if (copy != NULL) {
    memcpy(copy, value, len);
  }
  return copy;
}

static bool
starts_with(const char *value, const char *prefix)
{
  return strncmp(value, prefix, strlen(prefix)) == 0;
}

static int
mkdir_p(const char *path)
{
  char *copy = xstrdup(path);
  if (copy == NULL) {
    return -1;
  }

  for (char *p = copy + 1; *p != '\0'; ++p) {
    if (*p != '/') {
      continue;
    }

    *p = '\0';
    if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
      int err = errno;
      free(copy);
      errno = err;
      return -1;
    }
    *p = '/';
  }

  if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
    int err = errno;
    free(copy);
    errno = err;
    return -1;
  }

  free(copy);
  return 0;
}

static int
write_full(int fd, const void *buf, size_t len)
{
  const char *p = buf;
  size_t offset = 0;

  while (offset < len) {
    ssize_t rc = write(fd, p + offset, len - offset);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    offset += (size_t) rc;
  }

  return 0;
}

/* A store path is immutable and hash-addressed, so anything verified about its
 * contents stays true. Traversal components would escape that guarantee, and
 * tabs or newlines would corrupt the TSV cache format. */
static bool
path_is_safe_store_path(const char *path)
{
  if (path == NULL || !starts_with(path, STORE_PREFIX)) {
    return false;
  }

  if (strchr(path, '\n') != NULL || strchr(path, '\t') != NULL) {
    return false;
  }

  const char *p = path;
  while (*p != '\0') {
    while (*p == '/') {
      ++p;
    }
    if (*p == '\0') {
      break;
    }

    const char *end = strchrnul(p, '/');
    size_t len = (size_t) (end - p);
    if ((len == 1 && p[0] == '.') || (len == 2 && p[0] == '.' && p[1] == '.')) {
      return false;
    }
    p = end;
  }

  return true;
}

static bool
field_is_safe_soname(const char *soname)
{
  return soname != NULL
    && soname[0] != '\0'
    && strchr(soname, '/') == NULL
    && strchr(soname, '\n') == NULL
    && strchr(soname, '\t') == NULL;
}

static void
free_dynamic_info(struct dynamic_info *info)
{
  free(info->needed);
  memset(info, 0, sizeof(*info));
}

static void
unload_elf_image(struct elf_image *image)
{
  if (image->data != NULL) {
    munmap(image->data, image->size);
  }
  image->data = NULL;
  image->size = 0;
}

/* Always resolved against the daemon's own root. Reading through
 * /proc/<pid>/root would let a client bind-mount over a store path inside an
 * unprivileged mount namespace and forge the ELF metadata being verified.
 *
 * The realpath() check keeps a store symlink from pointing the read outside the
 * store: the link is immutable, but a target outside the store is not. */
static bool
load_elf_image(const char *path, struct elf_image *image)
{
  memset(image, 0, sizeof(*image));

  char *resolved = realpath(path, NULL);
  if (resolved == NULL) {
    return false;
  }
  bool safe = path_is_safe_store_path(resolved);
  free(resolved);
  if (!safe) {
    return false;
  }

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < (off_t) sizeof(Elf64_Ehdr)) {
    close(fd);
    return false;
  }

  void *data = mmap(NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (data == MAP_FAILED) {
    return false;
  }

  image->data = data;
  image->size = (size_t) st.st_size;
  return true;
}

static bool
elf_bounds_ok(const struct elf_image *image, size_t off, size_t size)
{
  return off <= image->size && size <= image->size - off;
}

static bool
vaddr_to_offset(const struct elf_image *image, const Elf64_Phdr *phdrs, size_t phnum,
                Elf64_Addr vaddr, size_t *offset_out)
{
  for (size_t i = 0; i < phnum; ++i) {
    const Elf64_Phdr *ph = &phdrs[i];
    if (ph->p_type != PT_LOAD) {
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
parse_dynamic_info(const struct elf_image *image, struct dynamic_info *info)
{
  memset(info, 0, sizeof(*info));

  if (!elf_bounds_ok(image, 0, sizeof(Elf64_Ehdr))) {
    return false;
  }

  const Elf64_Ehdr *ehdr = image->data;
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0
      || ehdr->e_ident[EI_CLASS] != ELFCLASS64
      || ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
    return false;
  }

  if (!elf_bounds_ok(image, ehdr->e_phoff, ehdr->e_phnum * sizeof(Elf64_Phdr))) {
    return false;
  }

  const Elf64_Phdr *phdrs = (const Elf64_Phdr *) ((const char *) image->data + ehdr->e_phoff);
  const Elf64_Dyn *dynamic = NULL;
  size_t dynamic_count = 0;

  for (size_t i = 0; i < ehdr->e_phnum; ++i) {
    if (phdrs[i].p_type != PT_DYNAMIC) {
      continue;
    }
    if (!elf_bounds_ok(image, phdrs[i].p_offset, phdrs[i].p_filesz)) {
      return false;
    }
    dynamic = (const Elf64_Dyn *) ((const char *) image->data + phdrs[i].p_offset);
    dynamic_count = phdrs[i].p_filesz / sizeof(Elf64_Dyn);
    break;
  }

  if (dynamic == NULL) {
    return false;
  }

  Elf64_Addr strtab_vaddr = 0;
  size_t strsz = 0;
  Elf64_Xword soname_off = 0;
  Elf64_Xword runpath_off = 0;
  bool have_soname = false;
  size_t needed_cap = 0;

  for (size_t i = 0; i < dynamic_count && dynamic[i].d_tag != DT_NULL; ++i) {
    switch (dynamic[i].d_tag) {
      case DT_STRTAB:
        strtab_vaddr = dynamic[i].d_un.d_ptr;
        break;
      case DT_STRSZ:
        strsz = (size_t) dynamic[i].d_un.d_val;
        break;
      case DT_SONAME:
        soname_off = dynamic[i].d_un.d_val;
        have_soname = true;
        break;
      case DT_RUNPATH:
        runpath_off = dynamic[i].d_un.d_val;
        info->has_runpath = true;
        break;
      case DT_RPATH:
        info->has_rpath = true;
        break;
      case DT_NEEDED:
        if (info->needed_count == needed_cap) {
          size_t next_cap = needed_cap == 0 ? 8 : needed_cap * 2;
          const char **needed = realloc(info->needed, next_cap * sizeof(*needed));
          if (needed == NULL) {
            free_dynamic_info(info);
            return false;
          }
          info->needed = needed;
          needed_cap = next_cap;
        }
        info->needed[info->needed_count++] = (const char *) (uintptr_t) dynamic[i].d_un.d_val;
        break;
      default:
        break;
    }
  }

  size_t strtab_off = 0;
  if (strtab_vaddr == 0 || !vaddr_to_offset(image, phdrs, ehdr->e_phnum, strtab_vaddr, &strtab_off)) {
    free_dynamic_info(info);
    return false;
  }

  if (strsz == 0 || !elf_bounds_ok(image, strtab_off, strsz)) {
    free_dynamic_info(info);
    return false;
  }

  info->strtab = (const char *) image->data + strtab_off;
  info->strtab_size = strsz;

  /* Strings read below are only guaranteed terminated inside the mapping if the
   * table itself ends in NUL. */
  if (info->strtab[strsz - 1] != '\0') {
    free_dynamic_info(info);
    return false;
  }

  if (have_soname && soname_off < strsz) {
    info->soname = info->strtab + soname_off;
  }
  if (info->has_runpath) {
    if (runpath_off >= strsz) {
      free_dynamic_info(info);
      return false;
    }
    info->runpath = info->strtab + runpath_off;
  }

  for (size_t i = 0; i < info->needed_count; ++i) {
    Elf64_Xword off = (Elf64_Xword) (uintptr_t) info->needed[i];
    if (off >= strsz) {
      free_dynamic_info(info);
      return false;
    }
    info->needed[i] = info->strtab + off;
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
  if (parse_dynamic_info(&image, &info)) {
    if (info.soname != NULL) {
      match = strcmp(info.soname, soname) == 0;
    } else {
      const char *base = strrchr(path, '/');
      match = strcmp(base != NULL ? base + 1 : path, soname) == 0;
    }
    free_dynamic_info(&info);
  }

  unload_elf_image(&image);
  return match;
}

/* A colon-separated search path is usable only if every entry is an immutable
 * store path with no dynamic string tokens. $ORIGIN and friends are rejected
 * rather than expanded so the cached answer cannot depend on load context. */
static bool
search_path_is_cacheable(const char *search_path)
{
  if (search_path == NULL || search_path[0] == '\0') {
    return false;
  }

  const char *entry = search_path;
  while (true) {
    const char *end = strchrnul(entry, ':');
    size_t len = (size_t) (end - entry);

    if (len == 0) {
      /* An empty entry means the current directory. */
      return false;
    }

    char *dir = strndup(entry, len);
    if (dir == NULL) {
      return false;
    }

    bool ok = strchr(dir, '$') == NULL && path_is_safe_store_path(dir);
    free(dir);
    if (!ok) {
      return false;
    }

    if (*end == '\0') {
      break;
    }
    entry = end + 1;
  }

  return true;
}

/* A symlink inside a store directory is itself immutable: Nix hashes the link's
 * target string, so the link and where it points are both fixed by the store
 * path. Following it is therefore safe and is what glibc does. What must not be
 * cached is the resolved target when it lands outside the store, since only the
 * store gives the immutability the cache assumes. */
enum soname_probe {
  SONAME_ABSENT,
  SONAME_SAFE,
  SONAME_UNSAFE,
};

/* A directory can hold a regular file matching soname whose realpath()
 * escapes the store (an attacker-built package can put anything it wants
 * inside its own store paths). glibc does not care where a match resolves:
 * it loads the first directory with a matching name, unconditionally. So an
 * unsafe match here is not "not found" for search purposes -- it is exactly
 * what glibc would have taken, and the caller must stop rather than keep
 * looking at later directories, or it caches a directory glibc would never
 * have reached. */
static enum soname_probe
directory_holds_soname(const char *dir, const char *soname)
{
  char *candidate = NULL;
  if (asprintf(&candidate, "%s/%s", dir, soname) < 0) {
    return SONAME_ABSENT;
  }

  struct stat st;
  bool exists = stat(candidate, &st) == 0 && S_ISREG(st.st_mode);
  enum soname_probe result = SONAME_ABSENT;

  if (exists) {
    char *resolved = realpath(candidate, NULL);
    result = (resolved != NULL && path_is_safe_store_path(resolved)) ? SONAME_SAFE : SONAME_UNSAFE;
    free(resolved);
  }

  free(candidate);
  return result;
}

/* Walks a search path and returns the first directory holding the soname.
 * Returning the first hit is what makes the client's claim checkable: glibc
 * takes the same first hit, so any earlier match means the claim is wrong.
 * Sets *unsafe and returns NULL if that first hit resolves outside the
 * store: the caller must treat this as a hard stop, not as absence. */
static char *
first_hit_in_search_path(const char *search_path, const char *soname, bool *unsafe)
{
  if (search_path == NULL) {
    return NULL;
  }

  const char *entry = search_path;
  while (true) {
    const char *end = strchrnul(entry, ':');
    size_t len = (size_t) (end - entry);

    if (len > 0) {
      char *dir = strndup(entry, len);
      if (dir != NULL) {
        switch (directory_holds_soname(dir, soname)) {
          case SONAME_SAFE: {
            char *hit = NULL;
            if (asprintf(&hit, "%s/%s", dir, soname) < 0) {
              hit = NULL;
            }
            free(dir);
            return hit;
          }
          case SONAME_UNSAFE:
            free(dir);
            *unsafe = true;
            return NULL;
          case SONAME_ABSENT:
            break;
        }
      }
      free(dir);
    }

    if (*end == '\0') {
      break;
    }
    entry = end + 1;
  }

  return NULL;
}

/* Must stay byte-identical to cache_scope_key() in nix-ld-cache-audit.c. */
static char *
cache_scope_key(const char *requester_path, const char *ld_library_path)
{
  char *key = NULL;
  if (asprintf(&key,
               "v2\nrequester=%s\nld_library_path=%s\n",
               requester_path,
               ld_library_path != NULL ? ld_library_path : "") < 0) {
    return NULL;
  }

  return key;
}

static char *
cache_file_path(const char *cache_dir, const char *requester_path, const char *ld_library_path)
{
  char *scope_key = cache_scope_key(requester_path, ld_library_path);
  if (scope_key == NULL) {
    return NULL;
  }

  uint64_t hash = fnv1a64(scope_key);
  free(scope_key);

  char *path = NULL;
  if (asprintf(&path, "%s/%016llx.tsv", cache_dir, (unsigned long long) hash) < 0) {
    return NULL;
  }

  return path;
}

static char *
read_scope_file(const char *cache_path, size_t *len_out)
{
  int fd = open(cache_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno != ENOENT) {
      return NULL;
    }
    char *empty = malloc(1);
    if (empty != NULL) {
      *len_out = 0;
    }
    return empty;
  }

  size_t cap = 8192;
  size_t len = 0;
  char *buf = malloc(cap);
  if (buf == NULL) {
    close(fd);
    return NULL;
  }

  while (true) {
    if (len == cap) {
      size_t next_cap = cap * 2;
      char *next = realloc(buf, next_cap);
      if (next == NULL) {
        free(buf);
        close(fd);
        return NULL;
      }
      buf = next;
      cap = next_cap;
    }

    ssize_t rc = read(fd, buf + len, cap - len);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      free(buf);
      close(fd);
      return NULL;
    }
    if (rc == 0) {
      break;
    }
    len += (size_t) rc;
  }

  close(fd);
  *len_out = len;
  return buf;
}

static void
write_scope_cache_reset(struct write_scope_cache *cache)
{
  free(cache->cache_path);
  free(cache->file_contents);
  memset(cache, 0, sizeof(*cache));
}

static struct write_scope_cache *
write_scope_cache_find(const char *cache_path)
{
  for (size_t i = 0; i < WRITE_SCOPE_CACHE_CAP; ++i) {
    struct write_scope_cache *cache = &write_scope_caches[i];
    if (cache->cache_path != NULL && strcmp(cache->cache_path, cache_path) == 0) {
      cache->last_used = ++write_scope_cache_tick;
      return cache;
    }
  }

  return NULL;
}

static struct write_scope_cache *
write_scope_cache_victim(void)
{
  struct write_scope_cache *victim = &write_scope_caches[0];

  for (size_t i = 0; i < WRITE_SCOPE_CACHE_CAP; ++i) {
    struct write_scope_cache *cache = &write_scope_caches[i];
    if (cache->cache_path == NULL) {
      return cache;
    }
    if (cache->last_used < victim->last_used) {
      victim = cache;
    }
  }

  return victim;
}

/* NULL `st` means the file does not currently exist. */
static bool
write_scope_cache_matches(const struct write_scope_cache *cache, const struct stat *st)
{
  if (st == NULL) {
    return !cache->exists;
  }

  return cache->exists && cache->dev == st->st_dev && cache->ino == st->st_ino
    && cache->size == st->st_size && cache->mtim.tv_sec == st->st_mtim.tv_sec
    && cache->mtim.tv_nsec == st->st_mtim.tv_nsec;
}

static void
write_scope_cache_set_stat(struct write_scope_cache *cache, const struct stat *st)
{
  cache->exists = st != NULL;
  if (st != NULL) {
    cache->dev = st->st_dev;
    cache->ino = st->st_ino;
    cache->size = st->st_size;
    cache->mtim = st->st_mtim;
  }
}

static struct write_scope_cache *
write_scope_cache_load(const char *cache_path)
{
  struct stat st;
  bool file_exists = stat(cache_path, &st) == 0;
  if (!file_exists && errno != ENOENT) {
    return NULL;
  }

  struct write_scope_cache *cache = write_scope_cache_find(cache_path);
  if (cache != NULL) {
    if (write_scope_cache_matches(cache, file_exists ? &st : NULL)) {
      return cache;
    }
    /* The file changed or vanished underneath us (an external rm, a
     * truncate, ...): a stale in-memory snapshot must not keep pretending
     * it reflects what is on disk. Fall through and reload it. */
    write_scope_cache_reset(cache);
  }

  size_t len = 0;
  char *contents = read_scope_file(cache_path, &len);
  if (contents == NULL) {
    return NULL;
  }

  if (cache == NULL) {
    cache = write_scope_cache_victim();
    write_scope_cache_reset(cache);
  }
  cache->cache_path = xstrdup(cache_path);
  if (cache->cache_path == NULL) {
    free(contents);
    return NULL;
  }
  cache->file_contents = contents;
  cache->file_len = len;
  cache->last_used = ++write_scope_cache_tick;
  write_scope_cache_set_stat(cache, file_exists ? &st : NULL);
  return cache;
}

static bool
write_scope_cache_contains_line(const struct write_scope_cache *cache,
                                const char *soname, const char *path)
{
  const char *p = cache->file_contents;
  const char *end = p + cache->file_len;
  size_t soname_len = strlen(soname);
  size_t path_len = strlen(path);

  while (p < end) {
    const char *newline = memchr(p, '\n', (size_t) (end - p));
    const char *line_end = newline != NULL ? newline : end;
    const char *tab = memchr(p, '\t', (size_t) (line_end - p));

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

static int
write_scope_cache_append_line(struct write_scope_cache *cache, const char *line, size_t line_len)
{
  char *contents = realloc(cache->file_contents, cache->file_len + line_len);
  if (contents == NULL) {
    return -1;
  }

  memcpy(contents + cache->file_len, line, line_len);
  cache->file_contents = contents;
  cache->file_len += line_len;
  cache->last_used = ++write_scope_cache_tick;
  return 0;
}

static void
commit_cache_entry(const char *cache_dir, const char *requester_path,
                   const char *ld_library_path, const char *soname, const char *path)
{
  /* mkdir_p is a handful of mkdir()+EEXIST syscalls; cache_dir does not
   * disappear once created, so pay that cost at most once per daemon
   * lifetime rather than on every commit -- this runs on every cache miss
   * system-wide. */
  static bool cache_dir_ready;
  if (!cache_dir_ready) {
    if (mkdir_p(cache_dir) != 0) {
      return;
    }
    cache_dir_ready = true;
  }

  char *cache_path = cache_file_path(cache_dir, requester_path, ld_library_path);
  if (cache_path == NULL) {
    return;
  }

  struct write_scope_cache *cache = write_scope_cache_load(cache_path);
  if (cache != NULL && write_scope_cache_contains_line(cache, soname, path)) {
    free(cache_path);
    return;
  }

  char *line = NULL;
  int line_len = asprintf(&line, "%s\t%s\n", soname, path);
  if (line_len > 0) {
    /* 0664: every audited process reads this file directly, and the group is
     * what grants the daemon write access across DynamicUser uid changes. */
    int fd = open(cache_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0664);
    if (fd >= 0) {
      /* One write so concurrent readers never observe a torn line. */
      if (write_full(fd, line, (size_t) line_len) != 0) {
        debugf("write failed requester=%s soname=%s", requester_path, soname);
      } else if (cache != NULL) {
        struct stat st;
        /* Re-stat the fd we just wrote through so the cache's own identity
         * tracks its own write, instead of appearing stale (and forcing a
         * pointless re-read) on the very next lookup in this scope. */
        if (write_scope_cache_append_line(cache, line, (size_t) line_len) != 0
            || fstat(fd, &st) != 0) {
          write_scope_cache_reset(cache);
        } else {
          write_scope_cache_set_stat(cache, &st);
        }
      }
      close(fd);
    }
  }

  free(line);
  free(cache_path);
}

/* Derives the resolution instead of checking a client's claim. The client sends
 * the requester, soname and LD_LIBRARY_PATH scope, but not the resolved path.
 *
 * glibc searches no-slash DT_NEEDED and dlopen names through the DT_RPATH
 * chain, LD_LIBRARY_PATH, the requester's DT_RUNPATH, ld.so.cache, then the
 * default directories. Only a prefix of that is reconstructible from immutable
 * data, so a resolution is derived only when the outcome is unambiguous:
 *
 *   - the requester has DT_RUNPATH, which per _dl_map_new_object (glibc
 *     elf/dl-load.c, `loader->l_info[DT_RUNPATH] == NULL` gate) suppresses the
 *     entire DT_RPATH chain, inherited and executable RPATH included;
 *   - every LD_LIBRARY_PATH and DT_RUNPATH entry is a token-free store path;
 *   - the first hit walking LD_LIBRARY_PATH then DT_RUNPATH is what glibc must
 *     also have taken, so no earlier directory could have won.
 *
 * A hit implies glibc never consulted ld.so.cache or the default directories,
 * neither of which is captured by the cache key. Anything else is refused
 * rather than guessed. Returns the resolved path, or NULL. */
static char *
derive_resolution(const char *requester_path, const char *soname,
                  const char *ld_library_path)
{
  struct elf_image image;
  if (!load_elf_image(requester_path, &image)) {
    debugf("reject reason=unreadable-requester requester=%s", requester_path);
    return NULL;
  }

  struct dynamic_info info;
  if (!parse_dynamic_info(&image, &info)) {
    debugf("reject reason=unparsable-requester requester=%s", requester_path);
    unload_elf_image(&image);
    return NULL;
  }

  char *hit = NULL;
  bool unsafe_hit = false;

  if (!info.has_runpath) {
    debugf("reject reason=no-runpath requester=%s soname=%s", requester_path, soname);
    goto out;
  }

  if (info.has_rpath) {
    debugf("reject reason=rpath-present requester=%s soname=%s", requester_path, soname);
    goto out;
  }

  if (!search_path_is_cacheable(info.runpath)) {
    debugf("reject reason=unsafe-runpath requester=%s soname=%s", requester_path, soname);
    goto out;
  }

  if (ld_library_path[0] != '\0') {
    if (!search_path_is_cacheable(ld_library_path)) {
      debugf("reject reason=unsafe-ld-library-path requester=%s soname=%s",
             requester_path, soname);
      goto out;
    }
    hit = first_hit_in_search_path(ld_library_path, soname, &unsafe_hit);
  }

  if (hit == NULL && !unsafe_hit) {
    hit = first_hit_in_search_path(info.runpath, soname, &unsafe_hit);
  }

  if (unsafe_hit) {
    /* glibc's first match, in LD_LIBRARY_PATH or RUNPATH, resolves outside
     * the store. That is what glibc would have loaded (or failed on); a
     * later directory's safe match is not what actually happens and must
     * not be cached in its place. */
    debugf("reject reason=unsafe-search-hit requester=%s soname=%s", requester_path, soname);
    goto out;
  }

  if (hit == NULL) {
    debugf("reject reason=no-hit-in-search-paths requester=%s soname=%s",
           requester_path, soname);
    goto out;
  }

  /* The hit came from a directory listing, so its name matches by construction;
   * this confirms the file really is the library that soname names. */
  if (!soname_matches(hit, soname)) {
    debugf("reject reason=soname-mismatch requester=%s soname=%s path=%s",
           requester_path, soname, hit);
    free(hit);
    hit = NULL;
    goto out;
  }

out:
  free_dynamic_info(&info);
  unload_elf_image(&image);
  return hit;
}

static void
process_message(struct connection *conn, const char *cache_dir)
{
  const char *requester_path = conn->payload;
  const char *soname = requester_path + conn->header.requester_len + 1;
  const char *ld_library_path = soname + conn->header.soname_len + 1;

  if (!path_is_safe_store_path(requester_path) || !field_is_safe_soname(soname)) {
    debugf("reject reason=invalid-fields pid=%ld", (long) conn->pid);
    return;
  }

  /* ld_library_path's cacheability is derive_resolution()'s own invariant
   * (checked there, with a specific reject reason) -- not re-checked here,
   * so that check stays the single point of truth instead of being shadowed
   * by a coarser one that fires first. */
  char *resolved = derive_resolution(requester_path, soname, ld_library_path);
  if (resolved == NULL) {
    return;
  }

  debugf("commit requester=%s soname=%s path=%s", requester_path, soname, resolved);
  commit_cache_entry(cache_dir, requester_path, ld_library_path, soname, resolved);
  free(resolved);
}

static void
connection_close(struct connection *conn)
{
  if (conn->fd >= 0) {
    close(conn->fd);
  }
  free(conn->payload);
  memset(conn, 0, sizeof(*conn));
  conn->fd = -1;
}

static bool
header_is_sane(const struct nix_ld_cache_msg *msg)
{
  return msg->magic == NIX_LD_CACHE_PROTOCOL_MAGIC
    && msg->version == NIX_LD_CACHE_PROTOCOL_VERSION
    && msg->requester_len > 0 && msg->requester_len <= NIX_LD_CACHE_PROTOCOL_MAX_FIELD
    && msg->soname_len > 0 && msg->soname_len <= NIX_LD_CACHE_PROTOCOL_MAX_FIELD
    && msg->ld_library_path_len <= NIX_LD_CACHE_PROTOCOL_MAX_FIELD;
}

/* Turns the contiguous wire payload into three NUL-terminated fields in place,
 * shifting from the right so nothing is overwritten before it is moved. */
static void
terminate_payload_fields(struct connection *conn)
{
  size_t rlen = conn->header.requester_len;
  size_t slen = conn->header.soname_len;
  size_t llen = conn->header.ld_library_path_len;
  char *buf = conn->payload;

  memmove(buf + rlen + 1, buf + rlen, slen + llen);
  memmove(buf + rlen + 1 + slen + 1, buf + rlen + 1 + slen, llen);
  buf[rlen] = '\0';
  buf[rlen + 1 + slen] = '\0';
  buf[rlen + 1 + slen + 1 + llen] = '\0';
}

/* Returns false when the connection is finished and should be dropped. */
static bool
connection_read(struct connection *conn, const char *cache_dir)
{
  while (true) {
    if (conn->state == CONN_READ_HEADER) {
      ssize_t rc = read(conn->fd, (char *) &conn->header + conn->header_got,
                        sizeof(conn->header) - conn->header_got);
      if (rc < 0) {
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
      }
      if (rc == 0) {
        return false;
      }

      conn->header_got += (size_t) rc;
      if (conn->header_got < sizeof(conn->header)) {
        continue;
      }

      if (!header_is_sane(&conn->header)) {
        return false;
      }

      conn->wire_len = (size_t) conn->header.requester_len
        + conn->header.soname_len
        + conn->header.ld_library_path_len;
      conn->payload_cap = conn->wire_len + 3;
      conn->payload = calloc(1, conn->payload_cap);
      if (conn->payload == NULL) {
        return false;
      }
      conn->payload_got = 0;
      conn->state = CONN_READ_PAYLOAD;
      continue;
    }

    ssize_t rc = read(conn->fd, conn->payload + conn->payload_got,
                      conn->wire_len - conn->payload_got);
    if (rc < 0) {
      return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    }
    if (rc == 0) {
      return false;
    }

    conn->payload_got += (size_t) rc;
    if (conn->payload_got < conn->wire_len) {
      continue;
    }

    terminate_payload_fields(conn);
    process_message(conn, cache_dir);
    return false;
  }
}

static int
listen_socket(const char *socket_path)
{
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(socket_path) >= sizeof(addr.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(addr.sun_path, socket_path);

  unlink(socket_path);
  /* umask around bind() avoids the window an after-the-fact chmod would leave. */
  mode_t old_umask = umask(0111);
  int rc = bind(fd, (const struct sockaddr *) &addr, sizeof(addr));
  umask(old_umask);
  if (rc != 0) {
    close(fd);
    return -1;
  }

  if (listen(fd, 128) != 0) {
    close(fd);
    unlink(socket_path);
    return -1;
  }

  return fd;
}

static void
accept_connections(int listen_fd, int epoll_fd, struct connection *conns, size_t *live_count)
{
  while (true) {
    int client = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client < 0) {
      return;
    }

    /* Slots are allocated by search, not indexed by fd: each connection holds
     * up to three descriptors, so keying on the fd value would cap concurrency
     * at a fraction of MAX_CONNECTIONS. */
    struct connection *conn = NULL;
    for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
      if (conns[i].fd < 0) {
        conn = &conns[i];
        break;
      }
    }

    if (conn == NULL) {
      debugf("reject reason=too-many-connections");
      close(client);
      continue;
    }

    conn->fd = client;
    conn->state = CONN_READ_HEADER;
    conn->deadline_ms = now_ms() + CONNECTION_TIMEOUT_MS;

    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0) {
      connection_close(conn);
      continue;
    }
    conn->pid = cred.pid;

    /* epoll carries the slot index, since the fd no longer implies it. */
    struct epoll_event ev = {
      .events = EPOLLIN | EPOLLRDHUP,
      .data.u32 = (uint32_t) (conn - conns),
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &ev) != 0) {
      connection_close(conn);
      continue;
    }

    ++*live_count;
  }
}

static int
next_timeout_ms(const struct connection *conns, size_t live_count)
{
  if (live_count == 0) {
    return -1;
  }

  uint64_t now = now_ms();
  uint64_t soonest = UINT64_MAX;
  for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
    if (conns[i].fd >= 0 && conns[i].deadline_ms < soonest) {
      soonest = conns[i].deadline_ms;
    }
  }

  if (soonest == UINT64_MAX) {
    return -1;
  }

  return soonest <= now ? 0 : (int) (soonest - now);
}

static void
expire_connections(struct connection *conns, size_t *live_count)
{
  uint64_t now = now_ms();
  for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
    if (conns[i].fd >= 0 && conns[i].deadline_ms <= now) {
      debugf("reject reason=timeout pid=%ld", (long) conns[i].pid);
      connection_close(&conns[i]);
      --*live_count;
    }
  }
}

int
main(int argc, char **argv)
{
  const char *socket_path = "/run/nix-ld-cache/learn.sock";
  const char *cache_dir = "/var/cache/nix-ld-cache";

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
      socket_path = argv[++i];
    } else if (strcmp(argv[i], "--cache-dir") == 0 && i + 1 < argc) {
      cache_dir = argv[++i];
    } else if (strcmp(argv[i], "--debug") == 0) {
      debug_logging = true;
    } else {
      fprintf(stderr, "usage: %s [--socket path] [--cache-dir path] [--debug]\n", argv[0]);
      return 2;
    }
  }

  const char *debug_env = getenv("NIX_LD_CACHE_DAEMON_DEBUG");
  if (debug_env != NULL && debug_env[0] != '\0' && strcmp(debug_env, "0") != 0) {
    debug_logging = true;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);

  int listen_fd = listen_socket(socket_path);
  if (listen_fd < 0) {
    perror("listen_socket");
    return 1;
  }

  int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd < 0) {
    perror("epoll_create1");
    close(listen_fd);
    unlink(socket_path);
    return 1;
  }

  struct epoll_event listen_ev = { .events = EPOLLIN, .data.u32 = LISTEN_SLOT };
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &listen_ev) != 0) {
    perror("epoll_ctl");
    close(epoll_fd);
    close(listen_fd);
    unlink(socket_path);
    return 1;
  }

  struct connection *conns = calloc(MAX_CONNECTIONS, sizeof(*conns));
  if (conns == NULL) {
    close(epoll_fd);
    close(listen_fd);
    unlink(socket_path);
    return 1;
  }
  for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
    conns[i].fd = -1;
  }

  size_t live_count = 0;
  struct epoll_event events[64];

  while (!stop_requested) {
    int n = epoll_wait(epoll_fd, events, (int) (sizeof(events) / sizeof(events[0])),
                       next_timeout_ms(conns, live_count));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    for (int i = 0; i < n; ++i) {
      if (events[i].data.u32 == LISTEN_SLOT) {
        accept_connections(listen_fd, epoll_fd, conns, &live_count);
        continue;
      }

      struct connection *conn = &conns[events[i].data.u32];
      if (conn->fd < 0) {
        continue;
      }

      if (!connection_read(conn, cache_dir)) {
        connection_close(conn);
        --live_count;
      }
    }

    expire_connections(conns, &live_count);
  }

  for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
    if (conns[i].fd >= 0) {
      connection_close(&conns[i]);
    }
  }

  free(conns);
  close(epoll_fd);
  close(listen_fd);
  unlink(socket_path);
  return 0;
}
