#define _GNU_SOURCE

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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "protocol.h"

/* One cached file per requester scope. glibc holds dl_load_lock across an entire
 * DT_NEEDED search, so a process resolves one requester at a time and a single
 * memoized scope covers every soname in that batch. */
struct scope_cache {
  char *requester_path;
  char *file_contents;
  size_t file_len;
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
path_is_absolute(const char *path)
{
  return path != NULL && path[0] == '/';
}

static bool
path_is_store_path(const char *path)
{
  return path != NULL && strncmp(path, "/nix/store/", strlen("/nix/store/")) == 0;
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

    bool ok = strchr(dir, '$') == NULL && path_is_store_path(dir);
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
requester_identity(uintptr_t cookie_value)
{
  const struct link_map *map = (const struct link_map *) cookie_value;

  /* The main executable's l_name is empty, so fall back to /proc/self/exe. */
  if (map != NULL && map->l_name != NULL && map->l_name[0] != '\0') {
    char *resolved = xstrdup(map->l_name);
    if (resolved != NULL) {
      return resolved;
    }
  }

  return readlink_dup("/proc/self/exe");
}

/* Mirrors the daemon's predicate: DT_RUNPATH must be present (which suppresses
 * the DT_RPATH chain in glibc), DT_RPATH must be absent, and every RUNPATH
 * entry must be a token-free store path. Anything else is not cacheable. */
static bool
requester_runpath_cacheable(uintptr_t cookie_value)
{
  const struct link_map *map = (const struct link_map *) cookie_value;
  if (map == NULL || map->l_ld == NULL) {
    return false;
  }

  const char *strtab = NULL;
  ElfW(Word) runpath_off = 0;
  size_t strsz = 0;
  bool have_runpath = false;
  bool have_rpath = false;

  for (const ElfW(Dyn) *dyn = map->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
    if (dyn->d_tag == DT_STRTAB) {
      strtab = (const char *) dyn->d_un.d_ptr;
    } else if (dyn->d_tag == DT_STRSZ) {
      strsz = (size_t) dyn->d_un.d_val;
    } else if (dyn->d_tag == DT_RUNPATH) {
      runpath_off = dyn->d_un.d_val;
      have_runpath = true;
    } else if (dyn->d_tag == DT_RPATH) {
      have_rpath = true;
    }
  }

  if (!have_runpath || have_rpath || strtab == NULL || runpath_off >= strsz) {
    return false;
  }

  /* glibc relocates DT_STRTAB's d_un.d_ptr in place, so it should already be a
   * mapped address; a non-absolute-looking pointer means that assumption broke
   * and the table must not be dereferenced. */
  if ((uintptr_t) strtab < 0x1000) {
    return false;
  }

  return search_path_is_cacheable(strtab + runpath_off);
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
cache_scope_key(const char *requester_path)
{
  const char *ld_library_path = getenv("LD_LIBRARY_PATH");

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
cache_file_path(const char *requester_path)
{
  char *dir = cache_dir_path();
  if (dir == NULL) {
    return NULL;
  }

  char *scope_key = cache_scope_key(requester_path);
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
  free(cached_scope.file_contents);
  memset(&cached_scope, 0, sizeof(cached_scope));
}

/* Loads and memoizes the scope's cache file. A process typically resolves many
 * sonames for one requester, so reading the file once per scope replaces one
 * open plus full scan per soname. Caller holds state_lock. */
static bool
scope_cache_load(const char *requester_path)
{
  if (cached_scope.requester_path != NULL
      && strcmp(cached_scope.requester_path, requester_path) == 0) {
    return cached_scope.file_contents != NULL;
  }

  scope_cache_reset();

  char *cache_path = cache_file_path(requester_path);
  if (cache_path == NULL) {
    return false;
  }

  size_t len = 0;
  char *contents = read_whole_file(cache_path, &len);
  free(cache_path);

  cached_scope.requester_path = xstrdup(requester_path);
  if (cached_scope.requester_path == NULL) {
    free(contents);
    return false;
  }

  cached_scope.file_contents = contents;
  cached_scope.file_len = len;
  return contents != NULL;
}

/* Scans the memoized scope for soname. The daemon writes each (soname, path)
 * pair once, so the first match is the only match and the scan stops there.
 * Caller holds state_lock. */
static char *
lookup_cache_entry(const char *requester_path, const char *soname)
{
  if (!scope_cache_load(requester_path)) {
    return NULL;
  }

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
 * itself, so this cannot influence what gets cached.
 *
 * With no socket configured there is no privileged writer to vouch for a
 * resolution, so nothing is submitted and the loader resolves normally. Writing
 * the cache directly from here would bypass every check the daemon performs. */
static int
submit_cache_entry(const char *requester_path, const char *soname)
{
  const char *socket_path = getenv("NIX_LD_AUDIT_SOCKET");
  if (socket_path == NULL || socket_path[0] == '\0') {
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
      errno = ETIMEDOUT;
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
    .requester_len = (uint32_t) strlen(requester_path),
    .soname_len = (uint32_t) strlen(soname),
  };

  int rc = send_full(fd, &msg, sizeof(msg));
  rc = rc == 0 ? send_full(fd, requester_path, msg.requester_len) : rc;
  rc = rc == 0 ? send_full(fd, soname, msg.soname_len) : rc;
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
  submit_cache_entry(requester_path, name);
  free(requester_path);
  return (char *) name;
}
