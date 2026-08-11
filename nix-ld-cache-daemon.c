#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "protocol.h"

static volatile sig_atomic_t stop_requested;

struct elf_image {
  void *data;
  size_t size;
};

struct dynamic_info {
  const char *strtab;
  size_t strtab_size;
  const char *soname;
  const char **needed;
  size_t needed_count;
};

static void
handle_signal(int signo)
{
  (void) signo;
  stop_requested = 1;
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
path_is_store_path(const char *path)
{
  return path != NULL && path[0] == '/' && starts_with(path, "/nix/store/");
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

static ssize_t
read_full(int fd, void *buf, size_t count)
{
  size_t offset = 0;
  char *out = buf;

  while (offset < count) {
    ssize_t rc = read(fd, out + offset, count - offset);
    if (rc == 0) {
      break;
    }
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    offset += (size_t) rc;
  }

  return (ssize_t) offset;
}

static bool
recv_string(int fd, uint32_t len, char **out)
{
  if (len == 0 || len > NIX_LD_CACHE_PROTOCOL_MAX_FIELD) {
    return false;
  }

  char *buf = calloc(1, (size_t) len + 1);
  if (buf == NULL) {
    return false;
  }

  ssize_t rc = read_full(fd, buf, len);
  if (rc != (ssize_t) len) {
    free(buf);
    return false;
  }

  *out = buf;
  return true;
}

static bool
read_msg(int fd, char **requester_path, char **soname, char **path)
{
  struct nix_ld_cache_msg msg;
  ssize_t rc = read_full(fd, &msg, sizeof(msg));
  if (rc != (ssize_t) sizeof(msg)) {
    return false;
  }

  if (msg.magic != NIX_LD_CACHE_PROTOCOL_MAGIC
      || msg.version != NIX_LD_CACHE_PROTOCOL_VERSION) {
    return false;
  }

  if (!recv_string(fd, msg.requester_len, requester_path)
      || !recv_string(fd, msg.soname_len, soname)
      || !recv_string(fd, msg.path_len, path)) {
    free(*requester_path);
    free(*soname);
    free(*path);
    *requester_path = NULL;
    *soname = NULL;
    *path = NULL;
    return false;
  }

  return true;
}

static void
free_dynamic_info(struct dynamic_info *info)
{
  free(info->needed);
  memset(info, 0, sizeof(*info));
}

static bool
load_elf_image(const char *path, struct elf_image *image)
{
  memset(image, 0, sizeof(*image));

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
    if (delta > ph->p_filesz) {
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

  if (soname_off < strsz) {
    info->soname = info->strtab + soname_off;
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
elf_needed_contains(const char *path, const char *soname)
{
  struct elf_image image;
  if (!load_elf_image(path, &image)) {
    return false;
  }

  struct dynamic_info info;
  bool match = false;
  if (parse_dynamic_info(&image, &info)) {
    for (size_t i = 0; i < info.needed_count; ++i) {
      if (strcmp(info.needed[i], soname) == 0) {
        match = true;
        break;
      }
    }
    free_dynamic_info(&info);
  }

  unload_elf_image(&image);
  return match;
}

static bool
elf_soname_matches(const char *path, const char *soname)
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

static char *
proc_read_file(pid_t pid, const char *name, size_t *size_out)
{
  char proc_path[64];
  snprintf(proc_path, sizeof(proc_path), "/proc/%ld/%s", (long) pid, name);

  int fd = open(proc_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return NULL;
  }

  size_t cap = 4096;
  size_t len = 0;
  char *buf = malloc(cap);
  if (buf == NULL) {
    close(fd);
    return NULL;
  }

  while (true) {
    if (len == cap) {
      size_t next_cap = cap * 2;
      if (next_cap > 1 << 20) {
        break;
      }
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
  if (size_out != NULL) {
    *size_out = len;
  }
  return buf;
}

static const char *
find_env_value(const char *envbuf, size_t envlen, const char *name)
{
  size_t namelen = strlen(name);
  const char *p = envbuf;
  const char *end = envbuf + envlen;

  while (p < end && *p != '\0') {
    size_t len = strnlen(p, (size_t) (end - p));
    if (len > namelen && memcmp(p, name, namelen) == 0 && p[namelen] == '=') {
      return p + namelen + 1;
    }
    p += len + 1;
  }

  return NULL;
}

static void
read_auxv_values(pid_t pid, unsigned long long *hwcap, unsigned long long *hwcap2)
{
  *hwcap = 0;
  *hwcap2 = 0;

  size_t size = 0;
  char *buf = proc_read_file(pid, "auxv", &size);
  if (buf == NULL) {
    return;
  }

  const Elf64_auxv_t *auxv = (const Elf64_auxv_t *) buf;
  size_t count = size / sizeof(*auxv);
  for (size_t i = 0; i < count; ++i) {
    if (auxv[i].a_type == AT_HWCAP) {
      *hwcap = (unsigned long long) auxv[i].a_un.a_val;
    } else if (auxv[i].a_type == AT_HWCAP2) {
      *hwcap2 = (unsigned long long) auxv[i].a_un.a_val;
    }
  }

  free(buf);
}

static char *
cache_scope_key_for_pid(const char *requester_path, pid_t pid)
{
  size_t envlen = 0;
  char *envbuf = proc_read_file(pid, "environ", &envlen);
  if (envbuf == NULL) {
    return NULL;
  }

  const char *ld_library_path = find_env_value(envbuf, envlen, "LD_LIBRARY_PATH");
  const char *glibc_tunables = find_env_value(envbuf, envlen, "GLIBC_TUNABLES");
  const char *ld_hwcap_mask = find_env_value(envbuf, envlen, "LD_HWCAP_MASK");
  unsigned long long hwcap = 0;
  unsigned long long hwcap2 = 0;
  read_auxv_values(pid, &hwcap, &hwcap2);

  char *key = NULL;
  if (asprintf(&key,
               "requester=%s\nld_library_path=%s\nglibc_tunables=%s\nld_hwcap_mask=%s\nhwcap=%llx\nhwcap2=%llx\n",
               requester_path,
               ld_library_path != NULL ? ld_library_path : "",
               glibc_tunables != NULL ? glibc_tunables : "",
               ld_hwcap_mask != NULL ? ld_hwcap_mask : "",
               hwcap,
               hwcap2) < 0) {
    key = NULL;
  }

  free(envbuf);
  return key;
}

static char *
cache_file_path(const char *cache_dir, const char *requester_path, pid_t pid)
{
  char *scope_key = cache_scope_key_for_pid(requester_path, pid);
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

static void
commit_cache_entry(const char *cache_dir, pid_t pid,
                   const char *requester_path, const char *soname, const char *path)
{
  if (mkdir_p(cache_dir) != 0) {
    return;
  }

  char *cache_path = cache_file_path(cache_dir, requester_path, pid);
  if (cache_path == NULL) {
    return;
  }

  if (cache_contains_line(cache_path, soname, path)) {
    free(cache_path);
    return;
  }

  int fd = open(cache_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd >= 0) {
    dprintf(fd, "%s\t%s\n", soname, path);
    close(fd);
  }

  free(cache_path);
}

static bool
valid_client_strings(const char *requester_path, const char *soname, const char *path)
{
  return requester_path != NULL
    && soname != NULL
    && path != NULL
    && requester_path[0] != '\0'
    && soname[0] != '\0'
    && path[0] != '\0'
    && strchr(soname, '/') == NULL
    && strchr(soname, '\n') == NULL
    && path_is_store_path(requester_path)
    && path_is_store_path(path);
}

static void
handle_client(int fd, const char *cache_dir)
{
  struct ucred cred;
  socklen_t cred_len = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0) {
    return;
  }

  char *requester_path = NULL;
  char *soname = NULL;
  char *path = NULL;
  if (!read_msg(fd, &requester_path, &soname, &path)) {
    goto out;
  }

  if (!valid_client_strings(requester_path, soname, path)) {
    goto out;
  }

  if (!elf_needed_contains(requester_path, soname)) {
    goto out;
  }

  if (!elf_soname_matches(path, soname)) {
    goto out;
  }

  commit_cache_entry(cache_dir, cred.pid, requester_path, soname, path);

out:
  free(requester_path);
  free(soname);
  free(path);
}

static int
listen_socket(const char *socket_path)
{
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

  unlink(socket_path);
  if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  if (chmod(socket_path, 0666) != 0 || listen(fd, 128) != 0) {
    close(fd);
    unlink(socket_path);
    return -1;
  }

  return fd;
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
    } else {
      fprintf(stderr, "usage: %s [--socket path] [--cache-dir path]\n", argv[0]);
      return 2;
    }
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  int fd = listen_socket(socket_path);
  if (fd < 0) {
    perror("listen_socket");
    return 1;
  }

  while (!stop_requested) {
    int client = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    handle_client(client, cache_dir);
    close(client);
  }

  close(fd);
  unlink(socket_path);
  return 0;
}
