#ifndef NIX_LD_CACHE_LINUX_SYSCALL_H
#define NIX_LD_CACHE_LINUX_SYSCALL_H

/* Raw Linux syscall layer for the freestanding audit module. The audit shared
 * object must carry no DT_NEEDED entries (see SYSCALL_ONLY.md), so everything
 * the kernel ABI needs — syscall numbers, argument registers, and the handful
 * of userspace-visible structs — is defined here instead of taken from libc.
 *
 * All wrappers return the raw kernel result: >= 0 on success, -errno on
 * failure. No errno variable exists in this module.
 */

#include <stddef.h>
#include <stdint.h>

#if defined(__x86_64__)

#define LNX_SYS_read 0
#define LNX_SYS_write 1
#define LNX_SYS_close 3
#define LNX_SYS_fstat 5
#define LNX_SYS_mmap 9
#define LNX_SYS_munmap 11
#define LNX_SYS_socket 41
#define LNX_SYS_connect 42
#define LNX_SYS_sendto 44
#define LNX_SYS_getsockopt 55
#define LNX_SYS_getuid 102
#define LNX_SYS_futex 202
#define LNX_SYS_openat 257
#define LNX_SYS_mkdirat 258
#define LNX_SYS_newfstatat 262
#define LNX_SYS_readlinkat 267
#define LNX_SYS_faccessat 269
#define LNX_SYS_ppoll 271

/* Issues Linux syscall nr with up to six arguments; returns the raw kernel
 * result (>= 0 on success, -errno on failure). */
static inline long
lnx_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  long ret;

  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

/* x86_64 kernel struct stat (arch/x86/include/uapi/asm/stat.h). */
struct lnx_stat {
  unsigned long st_dev;
  unsigned long st_ino;
  unsigned long st_nlink;
  unsigned int st_mode;
  unsigned int st_uid;
  unsigned int st_gid;
  unsigned int lnx_pad0;
  unsigned long st_rdev;
  long st_size;
  long st_blksize;
  long st_blocks;
  long st_atime_sec;
  long st_atime_nsec;
  long st_mtime_sec;
  long st_mtime_nsec;
  long st_ctime_sec;
  long st_ctime_nsec;
  long lnx_unused[3];
};

#elif defined(__aarch64__)

#define LNX_SYS_mkdirat 34
#define LNX_SYS_faccessat 48
#define LNX_SYS_openat 56
#define LNX_SYS_close 57
#define LNX_SYS_read 63
#define LNX_SYS_write 64
#define LNX_SYS_ppoll 73
#define LNX_SYS_readlinkat 78
#define LNX_SYS_newfstatat 79
#define LNX_SYS_fstat 80
#define LNX_SYS_futex 98
#define LNX_SYS_getuid 174
#define LNX_SYS_socket 198
#define LNX_SYS_connect 203
#define LNX_SYS_sendto 206
#define LNX_SYS_getsockopt 209
#define LNX_SYS_munmap 215
#define LNX_SYS_mmap 222

/* Issues Linux syscall nr with up to six arguments; returns the raw kernel
 * result (>= 0 on success, -errno on failure). */
static inline long
lnx_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  register long x4 __asm__("x4") = a5;
  register long x5 __asm__("x5") = a6;

  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                   : "memory", "cc");
  return x0;
}

/* aarch64 kernel struct stat (include/uapi/asm-generic/stat.h). */
struct lnx_stat {
  unsigned long st_dev;
  unsigned long st_ino;
  unsigned int st_mode;
  unsigned int st_nlink;
  unsigned int st_uid;
  unsigned int st_gid;
  unsigned long st_rdev;
  unsigned long lnx_pad1;
  long st_size;
  int st_blksize;
  int lnx_pad2;
  long st_blocks;
  long st_atime_sec;
  unsigned long st_atime_nsec;
  long st_mtime_sec;
  unsigned long st_mtime_nsec;
  long st_ctime_sec;
  unsigned long st_ctime_nsec;
  unsigned int lnx_unused4;
  unsigned int lnx_unused5;
};

#else
#error "nix-ld-cache audit module: unsupported architecture (x86_64 and aarch64 only)"
#endif

/* Values below are identical on x86_64 and aarch64 (asm-generic ABI). */

#define LNX_AT_FDCWD (-100)

#define LNX_O_RDONLY 0
#define LNX_O_WRONLY 1
#define LNX_O_CREAT 0x40
#define LNX_O_APPEND 0x400
#define LNX_O_CLOEXEC 0x80000
#define LNX_O_PATH 0x200000

#define LNX_R_OK 4

#define LNX_S_IFMT 0170000
#define LNX_S_IFREG 0100000
#define LNX_S_ISREG(mode) (((mode) & LNX_S_IFMT) == LNX_S_IFREG)

#define LNX_PROT_READ 0x1
#define LNX_PROT_WRITE 0x2
#define LNX_MAP_PRIVATE 0x02
#define LNX_MAP_ANONYMOUS 0x20

#define LNX_AF_UNIX 1
#define LNX_SOCK_STREAM 1
#define LNX_SOCK_CLOEXEC LNX_O_CLOEXEC
#define LNX_SOCK_NONBLOCK 0x800
#define LNX_SOL_SOCKET 1
#define LNX_SO_ERROR 4
#define LNX_MSG_NOSIGNAL 0x4000

#define LNX_POLLOUT 0x4

#define LNX_FUTEX_WAIT 0
#define LNX_FUTEX_WAKE 1
#define LNX_FUTEX_PRIVATE_FLAG 128

#define LNX_EINTR 4
#define LNX_EEXIST 17
#define LNX_EINPROGRESS 115

/* AF_UNIX socket address; sun_path is used only as a NUL-terminated string. */
struct lnx_sockaddr_un {
  unsigned short sun_family;
  char sun_path[108];
};

/* One fd's request/result flags for lnx_ppoll(). */
struct lnx_pollfd {
  int fd;
  short events;
  short revents;
};

/* Seconds/nanoseconds duration or deadline, as used by lnx_ppoll(). */
struct lnx_timespec {
  long tv_sec;
  long tv_nsec;
};

/* Raw read(2). */
static inline long
lnx_read(long fd, void *buf, size_t count)
{
  return lnx_syscall6(LNX_SYS_read, fd, (long) buf, (long) count, 0, 0, 0);
}

/* Raw write(2). */
static inline long
lnx_write(long fd, const void *buf, size_t count)
{
  return lnx_syscall6(LNX_SYS_write, fd, (long) buf, (long) count, 0, 0, 0);
}

/* Raw close(2). */
static inline long
lnx_close(long fd)
{
  return lnx_syscall6(LNX_SYS_close, fd, 0, 0, 0, 0, 0);
}

/* Raw openat(2). */
static inline long
lnx_openat(long dirfd, const char *path, long flags, long mode)
{
  return lnx_syscall6(LNX_SYS_openat, dirfd, (long) path, flags, mode, 0, 0);
}

/* Raw fstat(2). */
static inline long
lnx_fstat(long fd, struct lnx_stat *st)
{
  return lnx_syscall6(LNX_SYS_fstat, fd, (long) st, 0, 0, 0, 0);
}

/* Raw newfstatat(2) (the modern fstatat(2)/lstat(2) backend). */
static inline long
lnx_newfstatat(long dirfd, const char *path, struct lnx_stat *st, long flags)
{
  return lnx_syscall6(LNX_SYS_newfstatat, dirfd, (long) path, (long) st, flags, 0, 0);
}

/* Raw readlinkat(2). */
static inline long
lnx_readlinkat(long dirfd, const char *path, char *buf, size_t bufsiz)
{
  return lnx_syscall6(LNX_SYS_readlinkat, dirfd, (long) path, (long) buf, (long) bufsiz, 0, 0);
}

/* Raw faccessat(2). */
static inline long
lnx_faccessat(long dirfd, const char *path, long mode)
{
  return lnx_syscall6(LNX_SYS_faccessat, dirfd, (long) path, mode, 0, 0, 0);
}

/* Raw mkdirat(2). */
static inline long
lnx_mkdirat(long dirfd, const char *path, long mode)
{
  return lnx_syscall6(LNX_SYS_mkdirat, dirfd, (long) path, mode, 0, 0, 0);
}

/* Raw socket(2). */
static inline long
lnx_socket(long family, long type, long protocol)
{
  return lnx_syscall6(LNX_SYS_socket, family, type, protocol, 0, 0, 0);
}

/* Raw connect(2). */
static inline long
lnx_connect(long fd, const struct lnx_sockaddr_un *addr, size_t addrlen)
{
  return lnx_syscall6(LNX_SYS_connect, fd, (long) addr, (long) addrlen, 0, 0, 0);
}

/* Raw sendto(2). */
static inline long
lnx_sendto(long fd, const void *buf, size_t len, long flags)
{
  return lnx_syscall6(LNX_SYS_sendto, fd, (long) buf, (long) len, flags, 0, 0);
}

/* Raw getsockopt(2). */
static inline long
lnx_getsockopt(long fd, long level, long optname, void *optval, unsigned int *optlen)
{
  return lnx_syscall6(LNX_SYS_getsockopt, fd, level, optname, (long) optval, (long) optlen, 0);
}

/* Raw ppoll(2) with a NULL signal mask. */
static inline long
lnx_ppoll(struct lnx_pollfd *fds, unsigned long nfds, const struct lnx_timespec *timeout)
{
  /* sigsetsize is the kernel sigset size; ignored with a NULL mask. */
  return lnx_syscall6(LNX_SYS_ppoll, (long) fds, (long) nfds, (long) timeout, 0, 8, 0);
}

/* Raw mmap(2). Returns NULL on failure instead of MAP_FAILED. */
static inline void *
lnx_mmap(void *addr, size_t len, long prot, long flags, long fd, long offset)
{
  long rc = lnx_syscall6(LNX_SYS_mmap, (long) addr, (long) len, prot, flags, fd, offset);
  if ((unsigned long) rc >= (unsigned long) -4095L) {
    return NULL;
  }
  return (void *) rc;
}

/* Raw munmap(2). */
static inline long
lnx_munmap(void *addr, size_t len)
{
  return lnx_syscall6(LNX_SYS_munmap, (long) addr, (long) len, 0, 0, 0, 0);
}

/* Raw getuid(2). */
static inline long
lnx_getuid(void)
{
  return lnx_syscall6(LNX_SYS_getuid, 0, 0, 0, 0, 0, 0);
}

/* Raw futex(2), WAIT/WAKE ops only (as used by the mutex above it in
 * nix-ld-cache-audit.c). */
static inline long
lnx_futex(int *uaddr, long op, long val, const struct lnx_timespec *timeout)
{
  return lnx_syscall6(LNX_SYS_futex, (long) uaddr, op, val, (long) timeout, 0, 0);
}

#endif
