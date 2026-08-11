#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "protocol.h"

struct pending_candidate {
  char *path;
  unsigned int flag;
  struct pending_candidate *next;
};

struct requester_state;

struct pending_request {
  unsigned long long sequence;
  char *soname;
  struct pending_candidate *candidates;
  struct requester_state *owner;
  struct pending_request *next;
};

struct requester_state {
  uintptr_t cookie;
  char *requester_path;
  bool runpath_cacheable;
  bool runpath_checked;
  unsigned long long next_sequence;
  struct pending_request *stack_top;
  struct requester_state *next;
};

static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static struct requester_state *requester_states;

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

static bool
debug_enabled(void)
{
  const char *value = getenv("NIX_LD_AUDIT_DEBUG");
  return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
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
runpath_entry_is_cacheable(const char *entry, size_t len)
{
  return len > 0 && entry[0] == '/';
}

static const char *
search_flag_name(unsigned int flag)
{
  switch (flag) {
    case LA_SER_LIBPATH:
      return "libpath";
    case LA_SER_RUNPATH:
      return "runpath";
    case LA_SER_CONFIG:
      return "config";
    case LA_SER_DEFAULT:
      return "default";
    default:
      return "other";
  }
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
canonicalize_path(const char *path)
{
  if (path == NULL || path[0] == '\0') {
    return NULL;
  }

  if (strcmp(path, "/proc/self/exe") == 0) {
    return readlink_dup(path);
  }

  if (!path_is_absolute(path)) {
    return xstrdup(path);
  }

  return xstrdup(path);
}

static char *
requester_identity(uintptr_t cookie_value)
{
  const struct link_map *map = (const struct link_map *) cookie_value;

  if (map != NULL && map->l_name != NULL && map->l_name[0] != '\0') {
    char *resolved = canonicalize_path(map->l_name);
    if (resolved != NULL) {
      return resolved;
    }
  }

  return readlink_dup("/proc/self/exe");
}

static bool
requester_runpath_cacheable(uintptr_t cookie_value)
{
  const struct link_map *map = (const struct link_map *) cookie_value;
  if (map == NULL || map->l_ld == NULL) {
    return true;
  }

  const char *strtab = NULL;
  ElfW(Word) runpath_off = 0;
  ElfW(Word) rpath_off = 0;
  bool have_runpath = false;
  bool have_rpath = false;

  for (const ElfW(Dyn) *dyn = map->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
    if (dyn->d_tag == DT_STRTAB) {
      strtab = (const char *) dyn->d_un.d_ptr;
    } else if (dyn->d_tag == DT_RUNPATH) {
      runpath_off = dyn->d_un.d_val;
      have_runpath = true;
    } else if (dyn->d_tag == DT_RPATH) {
      rpath_off = dyn->d_un.d_val;
      have_rpath = true;
    }
  }

  if (!have_runpath && !have_rpath) {
    return true;
  }

  if (strtab == NULL) {
    return false;
  }

  const char *search_path = strtab + (have_runpath ? runpath_off : rpath_off);
  const char *entry = search_path;

  while (true) {
    const char *end = strchr(entry, ':');
    size_t len = end != NULL ? (size_t) (end - entry) : strlen(entry);

    if (!runpath_entry_is_cacheable(entry, len)) {
      return false;
    }

    if (end == NULL) {
      break;
    }

    entry = end + 1;
  }

  return true;
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
    if (mkdir(copy, 0700) != 0 && errno != EEXIST) {
      int err = errno;
      free(copy);
      errno = err;
      return -1;
    }
    *p = '/';
  }

  if (mkdir(copy, 0700) != 0 && errno != EEXIST) {
    int err = errno;
    free(copy);
    errno = err;
    return -1;
  }

  free(copy);
  return 0;
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

static char *
cache_scope_key(const char *requester_path)
{
  const char *ld_library_path = getenv("LD_LIBRARY_PATH");
  const char *glibc_tunables = getenv("GLIBC_TUNABLES");
  const char *ld_hwcapp_mask = getenv("LD_HWCAP_MASK");
  unsigned long long hwcap = (unsigned long long) getauxval(AT_HWCAP);
  unsigned long long hwcap2 = (unsigned long long) getauxval(AT_HWCAP2);

  char *key = NULL;
  if (asprintf(&key,
               "requester=%s\nld_library_path=%s\nglibc_tunables=%s\nld_hwcap_mask=%s\nhwcap=%llx\nhwcap2=%llx\n",
               requester_path,
               ld_library_path != NULL ? ld_library_path : "",
               glibc_tunables != NULL ? glibc_tunables : "",
               ld_hwcapp_mask != NULL ? ld_hwcapp_mask : "",
               hwcap,
               hwcap2) < 0) {
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
lookup_cache_entry(const char *requester_path, const char *soname)
{
  char *cache_path = cache_file_path(requester_path);
  if (cache_path == NULL) {
    return NULL;
  }

  FILE *fp = fopen(cache_path, "r");
  free(cache_path);
  if (fp == NULL) {
    return NULL;
  }

  char *line = NULL;
  size_t cap = 0;
  char *match = NULL;

  while (getline(&line, &cap, fp) >= 0) {
    char *tab = strchr(line, '\t');
    if (tab == NULL) {
      continue;
    }

    *tab = '\0';
    char *path = tab + 1;
    char *newline = strchr(path, '\n');
    if (newline != NULL) {
      *newline = '\0';
    }

    if (strcmp(line, soname) != 0) {
      continue;
    }

    if (!file_exists_readable(path)) {
      continue;
    }

    free(match);
    match = xstrdup(path);
  }

  free(line);
  fclose(fp);
  return match;
}

static int
write_cache_entry_local(const char *requester_path, const char *soname, const char *path)
{
  char *dir = cache_dir_path();
  if (dir == NULL) {
    return -1;
  }

  if (mkdir_p(dir) != 0) {
    int err = errno;
    free(dir);
    errno = err;
    return -1;
  }

  char *cache_path = cache_file_path(requester_path);
  if (cache_path == NULL) {
    free(dir);
    return -1;
  }

  int fd = open(cache_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  free(cache_path);
  free(dir);
  if (fd < 0) {
    return -1;
  }

  dprintf(fd, "%s\t%s\n", soname, path);
  close(fd);
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

static int
submit_cache_entry(const char *requester_path, const char *soname, const char *path)
{
  const char *daemonless = getenv("NIX_LD_AUDIT_DAEMONLESS");
  if (daemonless != NULL && daemonless[0] != '\0' && strcmp(daemonless, "0") != 0) {
    return write_cache_entry_local(requester_path, soname, path);
  }

  const char *socket_path = getenv("NIX_LD_AUDIT_SOCKET");
  if (socket_path == NULL || socket_path[0] == '\0') {
    return write_cache_entry_local(requester_path, soname, path);
  }

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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

  if (connect(fd, (const struct sockaddr *) &addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  struct nix_ld_cache_msg msg = {
    .magic = NIX_LD_CACHE_PROTOCOL_MAGIC,
    .version = NIX_LD_CACHE_PROTOCOL_VERSION,
    .requester_len = (uint32_t) strlen(requester_path),
    .soname_len = (uint32_t) strlen(soname),
    .path_len = (uint32_t) strlen(path),
  };

  int rc = write_full(fd, &msg, sizeof(msg));
  rc = rc == 0 ? write_full(fd, requester_path, msg.requester_len) : rc;
  rc = rc == 0 ? write_full(fd, soname, msg.soname_len) : rc;
  rc = rc == 0 ? write_full(fd, path, msg.path_len) : rc;
  close(fd);
  return rc;
}

static void
free_pending_candidates(struct pending_candidate *candidate)
{
  while (candidate != NULL) {
    struct pending_candidate *next = candidate->next;
    free(candidate->path);
    free(candidate);
    candidate = next;
  }
}

static void
free_pending_request(struct pending_request *request)
{
  if (request == NULL) {
    return;
  }

  free(request->soname);
  free_pending_candidates(request->candidates);
  free(request);
}

static void
free_request_queue(struct pending_request *request)
{
  while (request != NULL) {
    struct pending_request *next = request->next;
    free_pending_request(request);
    request = next;
  }
}

static void
clear_request_queues(void)
{
  struct requester_state *state = requester_states;
  while (state != NULL) {
    free_request_queue(state->stack_top);
    state->stack_top = NULL;
    state = state->next;
  }
}

static void
free_requester_states(void)
{
  struct requester_state *state = requester_states;
  requester_states = NULL;

  while (state != NULL) {
    struct requester_state *next = state->next;
    free_request_queue(state->stack_top);
    free(state->requester_path);
    free(state);
    state = next;
  }
}

static struct requester_state *
find_requester_state(uintptr_t cookie_value)
{
  for (struct requester_state *state = requester_states; state != NULL; state = state->next) {
    if (state->cookie == cookie_value) {
      return state;
    }
  }

  return NULL;
}

static struct requester_state *
get_or_create_requester_state(uintptr_t cookie_value)
{
  struct requester_state *state = find_requester_state(cookie_value);
  if (state != NULL) {
    return state;
  }

  state = calloc(1, sizeof(*state));
  if (state == NULL) {
    return NULL;
  }

  state->cookie = cookie_value;
  state->requester_path = requester_identity(cookie_value);
  state->runpath_cacheable = requester_runpath_cacheable(cookie_value);
  state->runpath_checked = true;
  state->next_sequence = 1;
  state->next = requester_states;
  requester_states = state;
  return state;
}

static void
push_request(struct requester_state *state, struct pending_request *request)
{
  request->next = state->stack_top;
  request->owner = state;
  state->stack_top = request;
}

static void
pop_request_top(struct requester_state *state)
{
  struct pending_request *request = state->stack_top;
  if (request == NULL) {
    return;
  }

  state->stack_top = request->next;
  free_pending_request(request);
}

static bool
pending_request_matches_candidate(const struct pending_request *request, const char *path)
{
  for (const struct pending_candidate *candidate = request->candidates;
       candidate != NULL;
       candidate = candidate->next) {
    if (strcmp(candidate->path, path) == 0) {
      return true;
    }
  }

  return false;
}

static void
record_candidate(uintptr_t cookie_value, const char *name, unsigned int flag)
{
  struct requester_state *state = find_requester_state(cookie_value);
  struct pending_request *request = state != NULL ? state->stack_top : NULL;
  if (request == NULL) {
    return;
  }

  for (const struct pending_candidate *candidate = request->candidates;
       candidate != NULL;
       candidate = candidate->next) {
    if (candidate->flag == flag && strcmp(candidate->path, name) == 0) {
      return;
    }
  }

  struct pending_candidate *candidate = calloc(1, sizeof(*candidate));
  if (candidate == NULL) {
    return;
  }

  candidate->path = xstrdup(name);
  if (candidate->path == NULL) {
    free(candidate);
    return;
  }

  candidate->flag = flag;
  candidate->next = request->candidates;
  request->candidates = candidate;
  debugf("observed %s candidate requester=%s soname=%s seq=%llu path=%s",
         search_flag_name(flag), state->requester_path, request->soname,
         request->sequence, name);
}

unsigned int
la_version(unsigned int version)
{
  return version >= LAV_CURRENT ? LAV_CURRENT : 0;
}

void
la_activity(uintptr_t *cookie, unsigned int flag)
{
  (void) cookie;

  if (flag != LA_ACT_CONSISTENT) {
    return;
  }

  pthread_mutex_lock(&state_lock);
  clear_request_queues();
  pthread_mutex_unlock(&state_lock);
}

char *
la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
  if (name == NULL || cookie == NULL) {
    return (char *) name;
  }

  if (flag == LA_SER_ORIG) {
    if (strchr(name, '/') != NULL) {
      return (char *) name;
    }

    pthread_mutex_lock(&state_lock);
    struct requester_state *state = get_or_create_requester_state(*cookie);
    char *requester_path = state != NULL ? xstrdup(state->requester_path) : NULL;
    bool runpath_cacheable = state != NULL && state->runpath_checked && state->runpath_cacheable;
    pthread_mutex_unlock(&state_lock);
    if (state == NULL || requester_path == NULL) {
      free(requester_path);
      return (char *) name;
    }

    if (!runpath_cacheable) {
      debugf("skip cache requester=%s soname=%s reason=unsafe-runpath",
             requester_path, name);
      free(requester_path);
      return (char *) name;
    }

    char *cached = lookup_cache_entry(requester_path, name);
    if (cached != NULL) {
      debugf("cache hit requester=%s soname=%s path=%s",
             requester_path, name, cached);
      free(requester_path);
      return cached;
    }

    struct pending_request *request = calloc(1, sizeof(*request));
    if (request == NULL) {
      free(requester_path);
      return (char *) name;
    }

    request->soname = xstrdup(name);
    if (request->soname == NULL) {
      free_pending_request(request);
      free(requester_path);
      return (char *) name;
    }

    pthread_mutex_lock(&state_lock);
    state = get_or_create_requester_state(*cookie);
    if (state == NULL) {
      pthread_mutex_unlock(&state_lock);
      free_pending_request(request);
      free(requester_path);
      return (char *) name;
    }
    request->sequence = state->next_sequence++;
    push_request(state, request);
    pthread_mutex_unlock(&state_lock);
    debugf("cache miss requester=%s soname=%s seq=%llu",
           requester_path, name, request->sequence);
    free(requester_path);
    return (char *) name;
  }

  if ((flag == LA_SER_LIBPATH
       || flag == LA_SER_RUNPATH
       || flag == LA_SER_CONFIG
       || flag == LA_SER_DEFAULT)
      && path_is_absolute(name)) {
    pthread_mutex_lock(&state_lock);
    record_candidate(*cookie, name, flag);
    pthread_mutex_unlock(&state_lock);
  }

  return (char *) name;
}

unsigned int
la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
  (void) lmid;
  (void) cookie;

  if (map == NULL || map->l_name == NULL || map->l_name[0] == '\0') {
    return 0;
  }

  pthread_mutex_lock(&state_lock);
  for (struct requester_state *state = requester_states; state != NULL; state = state->next) {
    struct pending_request *request = state->stack_top;
    if (request != NULL && pending_request_matches_candidate(request, map->l_name)) {
      debugf("learned requester=%s soname=%s seq=%llu path=%s",
             state->requester_path, request->soname, request->sequence, map->l_name);
      submit_cache_entry(state->requester_path, request->soname, map->l_name);
      pop_request_top(state);
      break;
    }
  }
  pthread_mutex_unlock(&state_lock);

  return 0;
}

unsigned int
la_objclose(uintptr_t *cookie)
{
  (void) cookie;
  return 0;
}
