#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "protocol.h"

#define STORE_PREFIX "/nix/store/"
#define RUN_PREFIX "/run/"

/* One cached file per requester scope. glibc holds dl_load_lock across an entire
 * DT_NEEDED search, so a process resolves one requester at a time and a single
 * memoized scope covers every soname in that batch. */
struct scope_cache {
  char *requester_path;
  char *ld_library_path;
  char *file_contents;
  size_t file_len;
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

static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static struct scope_cache cached_scope;
static bool debug_logging;
static bool debug_logging_resolved;

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

/* Resolved once: la_objsearch runs on the startup path this module exists to
 * speed up, so a getenv() per log call is measurable overhead. */
static bool
debug_enabled(void)
{
  if (!debug_logging_resolved) {
    const char *value = getenv("NIX_LD_AUDIT_DEBUG");
    debug_logging = value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
    debug_logging_resolved = true;
  }

  return debug_logging;
}

static void
debugf(const char *fmt, ...)
{
  if (!debug_enabled()) {
    return;
  }

  va_list ap;
  va_start(ap, fmt);
  flockfile(stderr);
  fputs("nix-ld-cache-audit: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  funlockfile(stderr);
  va_end(ap);
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

static bool
path_is_absolute(const char *path)
{
  return path != NULL && path[0] == '/';
}

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
    const char *end = strchrnul(entry, ':');
    size_t len = (size_t) (end - entry);

    if (len == 0) {
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

static bool
environment_is_cacheable(void)
{
  const char *ld_library_path = getenv("LD_LIBRARY_PATH");
  if (ld_library_path == NULL || ld_library_path[0] == '\0') {
    return true;
  }

  return search_path_is_cacheable(ld_library_path);
}

static char *
readlink_dup(const char *path)
{
  char buf[PATH_MAX];
  ssize_t len = readlink(path, buf, sizeof(buf) - 1);

  if (len < 0) {
    return NULL;
  }

  buf[len] = '\0';
  return xstrdup(buf);
}

static char *
requester_cache_path(const char *path)
{
  if (path != NULL && starts_with(path, RUN_PREFIX)) {
    char *resolved = realpath(path, NULL);
    if (resolved != NULL) {
      if (path_is_safe_store_path(resolved)) {
        return resolved;
      }
      free(resolved);
    }
  }

  return xstrdup(path);
}

static char *
requester_identity(uintptr_t cookie_value)
{
  const struct link_map *map = (const struct link_map *) cookie_value;

  /* The main executable's l_name is empty, so fall back to /proc/self/exe. */
  if (map != NULL && map->l_name != NULL && map->l_name[0] != '\0') {
    char *resolved = requester_cache_path(map->l_name);
    if (resolved != NULL) {
      return resolved;
    }
  }

  return readlink_dup("/proc/self/exe");
}

static void
free_dynamic_info(struct dynamic_info *info)
{
  free(info->needed);
  memset(info, 0, sizeof(*info));
}

static bool
parse_mapped_dynamic_info(uintptr_t cookie_value, struct dynamic_info *info)
{
  memset(info, 0, sizeof(*info));

  const struct link_map *map = (const struct link_map *) cookie_value;
  if (map == NULL || map->l_ld == NULL) {
    return false;
  }

  ElfW(Xword) soname_off = 0;
  ElfW(Xword) runpath_off = 0;
  bool have_soname = false;
  size_t needed_cap = 0;

  for (const ElfW(Dyn) *dyn = map->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
    switch (dyn->d_tag) {
      case DT_STRTAB:
        info->strtab = (const char *) dyn->d_un.d_ptr;
        break;
      case DT_STRSZ:
        info->strtab_size = (size_t) dyn->d_un.d_val;
        break;
      case DT_SONAME:
        soname_off = dyn->d_un.d_val;
        have_soname = true;
        break;
      case DT_RUNPATH:
        runpath_off = dyn->d_un.d_val;
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
        info->needed[info->needed_count++] = (const char *) (uintptr_t) dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (info->strtab == NULL || info->strtab_size == 0 || (uintptr_t) info->strtab < 0x1000) {
    free_dynamic_info(info);
    return false;
  }

  if (info->strtab[info->strtab_size - 1] != '\0') {
    free_dynamic_info(info);
    return false;
  }

  if (have_soname && soname_off < info->strtab_size) {
    info->soname = info->strtab + soname_off;
  }
  if (info->has_runpath) {
    if (runpath_off >= info->strtab_size) {
      free_dynamic_info(info);
      return false;
    }
    info->runpath = info->strtab + runpath_off;
  }

  for (size_t i = 0; i < info->needed_count; ++i) {
    ElfW(Xword) off = (ElfW(Xword)) (uintptr_t) info->needed[i];
    if (off >= info->strtab_size) {
      free_dynamic_info(info);
      return false;
    }
    info->needed[i] = info->strtab + off;
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

  bool ok = info.has_runpath && !info.has_rpath && search_path_is_cacheable(info.runpath);
  free_dynamic_info(&info);
  return ok;
}

static char *
cache_dir_path(void)
{
  const char *root = getenv("NIX_LD_AUDIT_CACHE_DIR");
  char *path;

  if (root != NULL && root[0] != '\0') {
    return xstrdup(root);
  }

  root = getenv("XDG_CACHE_HOME");
  if (root != NULL && root[0] != '\0') {
    if (asprintf(&path, "%s/nix-ld-cache", root) < 0) {
      return NULL;
    }
    return path;
  }

  root = getenv("HOME");
  if (root != NULL && root[0] != '\0') {
    if (asprintf(&path, "%s/.cache/nix-ld-cache", root) < 0) {
      return NULL;
    }
    return path;
  }

  if (asprintf(&path, "/var/tmp/nix-ld-cache-audit-%lu", (unsigned long) getuid()) < 0) {
    return NULL;
  }

  return path;
}

/* Must stay byte-identical to cache_scope_key() in nix-ld-cache-daemon.c;
 * any drift silently reads a scope the daemon never writes. */
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
cache_file_path(const char *requester_path, const char *ld_library_path)
{
  char *dir = cache_dir_path();
  if (dir == NULL) {
    return NULL;
  }

  char *scope_key = cache_scope_key(requester_path, ld_library_path);
  if (scope_key == NULL) {
    free(dir);
    return NULL;
  }

  uint64_t hash = fnv1a64(scope_key);
  char *path;
  if (asprintf(&path, "%s/%016llx.tsv", dir, (unsigned long long) hash) < 0) {
    free(scope_key);
    free(dir);
    return NULL;
  }

  free(scope_key);
  free(dir);
  return path;
}

static bool
file_exists_readable(const char *path)
{
  return path_is_absolute(path) && access(path, R_OK) == 0;
}

static char *
read_whole_file(const char *path, size_t *len_out)
{
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return NULL;
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
scope_cache_reset(void)
{
  free(cached_scope.requester_path);
  free(cached_scope.ld_library_path);
  free(cached_scope.file_contents);
  memset(&cached_scope, 0, sizeof(cached_scope));
}

/* Loads and memoizes the scope's cache file. Missing files are not memoized:
 * the daemon may create them after an earlier miss in the same process. */
static bool
scope_cache_load(const char *requester_path)
{
  const char *ld_library_path = getenv("LD_LIBRARY_PATH");
  if (ld_library_path == NULL) {
    ld_library_path = "";
  }

  if (cached_scope.requester_path != NULL
      && cached_scope.ld_library_path != NULL
      && strcmp(cached_scope.requester_path, requester_path) == 0
      && strcmp(cached_scope.ld_library_path, ld_library_path) == 0) {
    return cached_scope.file_contents != NULL;
  }

  scope_cache_reset();

  char *cache_path = cache_file_path(requester_path, ld_library_path);
  if (cache_path == NULL) {
    return false;
  }

  size_t len = 0;
  char *contents = read_whole_file(cache_path, &len);
  free(cache_path);
  if (contents == NULL) {
    return false;
  }

  cached_scope.requester_path = xstrdup(requester_path);
  cached_scope.ld_library_path = xstrdup(ld_library_path);
  if (cached_scope.requester_path == NULL || cached_scope.ld_library_path == NULL) {
    free(contents);
    scope_cache_reset();
    return false;
  }

  cached_scope.file_contents = contents;
  cached_scope.file_len = len;
  return true;
}

/* Scans the memoized scope for soname. Caller holds state_lock. */
static char *
scan_scope_cache(const char *soname)
{
  const char *p = cached_scope.file_contents;
  const char *end = p + cached_scope.file_len;
  size_t soname_len = strlen(soname);

  while (p < end) {
    const char *newline = memchr(p, '\n', (size_t) (end - p));
    const char *line_end = newline != NULL ? newline : end;

    const char *tab = memchr(p, '\t', (size_t) (line_end - p));
    if (tab != NULL
        && (size_t) (tab - p) == soname_len
        && memcmp(p, soname, soname_len) == 0) {
      char *path = strndup(tab + 1, (size_t) (line_end - tab - 1));
      if (path != NULL && file_exists_readable(path)) {
        return path;
      }
      free(path);
      return NULL;
    }

    if (newline == NULL) {
      break;
    }
    p = newline + 1;
  }

  return NULL;
}

/* The daemon appends to scope files asynchronously, so a loaded scope can become
 * stale after a miss. Retry once with a fresh read before falling back to glibc. */
static char *
lookup_cache_entry(const char *requester_path, const char *soname)
{
  if (!scope_cache_load(requester_path)) {
    return NULL;
  }

  char *path = scan_scope_cache(soname);
  if (path != NULL) {
    return path;
  }

  scope_cache_reset();
  if (!scope_cache_load(requester_path)) {
    return NULL;
  }

  return scan_scope_cache(soname);
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

static void
unload_elf_image(struct elf_image *image)
{
  if (image->data != NULL) {
    munmap(image->data, image->size);
  }
  image->data = NULL;
  image->size = 0;
}

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
parse_file_dynamic_info(const struct elf_image *image, struct dynamic_info *info)
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
  Elf64_Xword soname_off = 0;
  bool have_soname = false;

  for (size_t i = 0; i < dynamic_count && dynamic[i].d_tag != DT_NULL; ++i) {
    switch (dynamic[i].d_tag) {
      case DT_STRTAB:
        strtab_vaddr = dynamic[i].d_un.d_ptr;
        break;
      case DT_STRSZ:
        info->strtab_size = (size_t) dynamic[i].d_un.d_val;
        break;
      case DT_SONAME:
        soname_off = dynamic[i].d_un.d_val;
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

  info->strtab = (const char *) image->data + strtab_off;
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

static bool
directory_holds_soname(const char *dir, const char *soname)
{
  char *candidate = NULL;
  if (asprintf(&candidate, "%s/%s", dir, soname) < 0) {
    return false;
  }

  struct stat st;
  bool found = stat(candidate, &st) == 0 && S_ISREG(st.st_mode);
  if (found) {
    char *resolved = realpath(candidate, NULL);
    found = resolved != NULL && path_is_safe_store_path(resolved);
    free(resolved);
  }

  free(candidate);
  return found;
}

static char *
first_hit_in_search_path(const char *search_path, const char *soname)
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
      if (dir != NULL && directory_holds_soname(dir, soname)) {
        char *hit = NULL;
        if (asprintf(&hit, "%s/%s", dir, soname) < 0) {
          hit = NULL;
        }
        free(dir);
        return hit;
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

static char *
derive_resolution(uintptr_t cookie_value, const char *requester_path, const char *soname)
{
  if (!path_is_safe_store_path(requester_path) || !field_is_safe_soname(soname)) {
    debugf("daemonless reject reason=invalid-fields requester=%s soname=%s",
           requester_path, soname);
    return NULL;
  }

  struct dynamic_info info;
  if (!parse_mapped_dynamic_info(cookie_value, &info)) {
    debugf("daemonless reject reason=unparsable-requester requester=%s soname=%s",
           requester_path, soname);
    return NULL;
  }

  char *hit = NULL;
  const char *ld_library_path = getenv("LD_LIBRARY_PATH");

  if (!info.has_runpath) {
    debugf("daemonless reject reason=no-runpath requester=%s soname=%s", requester_path, soname);
    goto out;
  }

  if (info.has_rpath) {
    debugf("daemonless reject reason=rpath-present requester=%s soname=%s", requester_path, soname);
    goto out;
  }

  if (!search_path_is_cacheable(info.runpath)) {
    debugf("daemonless reject reason=unsafe-runpath requester=%s soname=%s", requester_path, soname);
    goto out;
  }

  if (ld_library_path != NULL && ld_library_path[0] != '\0') {
    if (!search_path_is_cacheable(ld_library_path)) {
      debugf("daemonless reject reason=unsafe-ld-library-path requester=%s soname=%s",
             requester_path, soname);
      goto out;
    }
    hit = first_hit_in_search_path(ld_library_path, soname);
  }

  if (hit == NULL) {
    hit = first_hit_in_search_path(info.runpath, soname);
  }

  if (hit == NULL) {
    debugf("daemonless reject reason=no-hit-in-search-paths requester=%s soname=%s",
           requester_path, soname);
    goto out;
  }

  if (!soname_matches(hit, soname)) {
    debugf("daemonless reject reason=soname-mismatch requester=%s soname=%s path=%s",
           requester_path, soname, hit);
    free(hit);
    hit = NULL;
  }

out:
  free_dynamic_info(&info);
  return hit;
}

static bool
cache_contains_line(const char *cache_path, const char *soname, const char *path)
{
  FILE *fp = fopen(cache_path, "r");
  if (fp == NULL) {
    return false;
  }

  char *line = NULL;
  size_t cap = 0;
  bool found = false;

  while (getline(&line, &cap, fp) >= 0) {
    char *tab = strchr(line, '\t');
    if (tab == NULL) {
      continue;
    }
    *tab = '\0';
    char *value = tab + 1;
    char *newline = strchr(value, '\n');
    if (newline != NULL) {
      *newline = '\0';
    }
    if (strcmp(line, soname) == 0 && strcmp(value, path) == 0) {
      found = true;
      break;
    }
  }

  free(line);
  fclose(fp);
  return found;
}

static int
commit_daemonless_cache_entry(const char *requester_path, const char *soname, const char *path)
{
  char *cache_dir = cache_dir_path();
  if (cache_dir == NULL) {
    return -1;
  }

  int rc = mkdir_p(cache_dir);
  free(cache_dir);
  if (rc != 0) {
    return -1;
  }

  const char *ld_library_path = getenv("LD_LIBRARY_PATH");
  if (ld_library_path == NULL) {
    ld_library_path = "";
  }

  char *cache_path = cache_file_path(requester_path, ld_library_path);
  if (cache_path == NULL) {
    return -1;
  }

  if (cache_contains_line(cache_path, soname, path)) {
    free(cache_path);
    return 0;
  }

  char *line = NULL;
  int line_len = asprintf(&line, "%s\t%s\n", soname, path);
  if (line_len < 0) {
    free(cache_path);
    return -1;
  }

  int fd = open(cache_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0664);
  if (fd < 0) {
    free(line);
    free(cache_path);
    return -1;
  }

  rc = write_full(fd, line, (size_t) line_len);
  close(fd);
  free(line);
  free(cache_path);
  return rc;
}

static void
invalidate_scope_cache(const char *requester_path)
{
  pthread_mutex_lock(&state_lock);
  if (cached_scope.requester_path != NULL
      && strcmp(cached_scope.requester_path, requester_path) == 0) {
    scope_cache_reset();
  }
  pthread_mutex_unlock(&state_lock);
}

static bool
daemonless_enabled(void)
{
  const char *value = getenv("NIX_LD_AUDIT_DAEMONLESS");
  return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}

static int
submit_daemonless_cache_entry(uintptr_t cookie_value, const char *requester_path, const char *soname)
{
  char *resolved = derive_resolution(cookie_value, requester_path, soname);
  if (resolved == NULL) {
    return 0;
  }

  debugf("daemonless commit requester=%s soname=%s path=%s", requester_path, soname, resolved);
  int rc = commit_daemonless_cache_entry(requester_path, soname, resolved);
  if (rc == 0) {
    invalidate_scope_cache(requester_path);
  }
  free(resolved);
  return rc;
}

/* MSG_NOSIGNAL keeps a daemon-side disconnect from raising SIGPIPE in the
 * audited process, which would kill an unrelated user program at startup. */
static int
send_full(int fd, const void *buf, size_t len)
{
  const char *p = buf;
  size_t offset = 0;

  while (offset < len) {
    ssize_t rc = send(fd, p + offset, len - offset, MSG_NOSIGNAL);
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

/* Reports {requester, soname} and nothing else: the daemon derives the path
 * itself, so this cannot influence what gets cached. Daemonless mode mirrors
 * that derivation locally and writes only to the configured per-user cache. */
static int
submit_cache_entry(uintptr_t cookie_value, const char *requester_path, const char *soname)
{
  if (daemonless_enabled()) {
    return submit_daemonless_cache_entry(cookie_value, requester_path, soname);
  }

  const char *socket_path = getenv("NIX_LD_AUDIT_SOCKET");
  if (socket_path == NULL || socket_path[0] == '\0') {
    return 0;
  }

  const char *ld_library_path = getenv("LD_LIBRARY_PATH");
  if (ld_library_path == NULL) {
    ld_library_path = "";
  }

  size_t requester_len = strlen(requester_path);
  size_t soname_len = strlen(soname);
  size_t ld_library_path_len = strlen(ld_library_path);
  if (requester_len > NIX_LD_CACHE_PROTOCOL_MAX_FIELD
      || soname_len > NIX_LD_CACHE_PROTOCOL_MAX_FIELD
      || ld_library_path_len > NIX_LD_CACHE_PROTOCOL_MAX_FIELD) {
    return 0;
  }

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

  /* Non-blocking connect bounded by poll(): a saturated daemon must not stall
   * process startup, and this runs on every cache miss. */
  if (connect(fd, (const struct sockaddr *) &addr, sizeof(addr)) != 0) {
    if (errno != EINPROGRESS) {
      close(fd);
      return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int rc = poll(&pfd, 1, 200);
    if (rc <= 0) {
      close(fd);
      errno = rc == 0 ? ETIMEDOUT : errno;
      return -1;
    }

    int err = 0;
    socklen_t errlen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0 || err != 0) {
      close(fd);
      errno = err != 0 ? err : EIO;
      return -1;
    }
  }

  struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  struct nix_ld_cache_msg msg = {
    .magic = NIX_LD_CACHE_PROTOCOL_MAGIC,
    .version = NIX_LD_CACHE_PROTOCOL_VERSION,
    .requester_len = (uint32_t) requester_len,
    .soname_len = (uint32_t) soname_len,
    .ld_library_path_len = (uint32_t) ld_library_path_len,
  };

  int rc = send_full(fd, &msg, sizeof(msg));
  rc = rc == 0 ? send_full(fd, requester_path, msg.requester_len) : rc;
  rc = rc == 0 ? send_full(fd, soname, msg.soname_len) : rc;
  rc = rc == 0 ? send_full(fd, ld_library_path, msg.ld_library_path_len) : rc;
  close(fd);
  return rc;
}

unsigned int
la_version(unsigned int version)
{
  /* Returning the caller's version keeps the module usable on an older glibc
   * rather than silently disabling itself. */
  return version < LAV_CURRENT ? version : LAV_CURRENT;
}

char *
la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
  if (name == NULL || cookie == NULL || flag != LA_SER_ORIG) {
    return (char *) name;
  }

  if (strchr(name, '/') != NULL) {
    return (char *) name;
  }

  if (!environment_is_cacheable()) {
    debugf("skip cache soname=%s reason=unsafe-ld-library-path", name);
    return (char *) name;
  }

  if (!requester_runpath_cacheable(*cookie)) {
    debugf("skip cache soname=%s reason=unsafe-runpath", name);
    return (char *) name;
  }

  char *requester_path = requester_identity(*cookie);
  if (requester_path == NULL) {
    return (char *) name;
  }

  pthread_mutex_lock(&state_lock);
  char *cached = lookup_cache_entry(requester_path, name);
  pthread_mutex_unlock(&state_lock);

  if (cached != NULL) {
    debugf("cache hit requester=%s soname=%s path=%s", requester_path, name, cached);
    free(requester_path);
    /* glibc never frees this; the leak is one allocation per distinct soname
     * per process and the audit ABI offers no hook to reclaim it. */
    return cached;
  }

  debugf("cache miss requester=%s soname=%s", requester_path, name);

  /* Submitted outside state_lock: this talks to the daemon, and blocking here
   * with the lock held would serialize every other thread's resolution. */
  submit_cache_entry(*cookie, requester_path, name);
  free(requester_path);
  return (char *) name;
}
