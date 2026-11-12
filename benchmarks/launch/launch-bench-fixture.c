/* Launch-mode benchmark fixture: one freestanding static binary, run either
 * natively inside a chroot or as the init of `ginux launch`.
 *
 *   fixture <class> <passes>
 *
 * It prints one line, `RESULT class=<c> passes=<n> ns=<timed> ops=<n> ...`,
 * where only the timed region of the class is counted (setup is excluded).
 * The image tree lives under /img (read-only image root), owned storage under
 * /work. `fixture noop` exits at once (the fork+exec target). */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e, word f)
{
    register word r10 __asm__("r10") = d;
    register word r8 __asm__("r8") = e;
    register word r9 __asm__("r9") = f;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c),
                     "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}
#define SC(n, a, b, c) call(n, (word)(a), (word)(b), (word)(c), 0, 0, 0)
#define SC4(n, a, b, c, d) call(n, (word)(a), (word)(b), (word)(c), (word)(d), 0, 0)
#define SC5(n, a, b, c, d, e) call(n, (word)(a), (word)(b), (word)(c), (word)(d), (word)(e), 0)

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_lseek = 8,
    SYS_mmap = 9, SYS_munmap = 11, SYS_pread64 = 17, SYS_pipe = 22,
    SYS_getpid = 39, SYS_fork = 57, SYS_execve = 59, SYS_exit = 60,
    SYS_wait4 = 61, SYS_mkdir = 83, SYS_unlink = 87, SYS_futex = 202,
    SYS_getdents64 = 217, SYS_clock_gettime = 228, SYS_exit_group = 231,
    SYS_newfstatat = 262, SYS_statx = 332, SYS_clone = 56,
};
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0200000
#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

static char buffer[65536];
static char st[256] __attribute__((aligned(8)));
static char stx[256] __attribute__((aligned(8)));
static long ts[2];
static char dents[8192] __attribute__((aligned(8)));
static char archive[16 << 20];

static long now(void)
{
    SC(SYS_clock_gettime, 1, ts, 0);
    return ts[0] * 1000000000L + ts[1];
}
static unsigned long length(const char *s) { unsigned long n = 0; while (s[n]) ++n; return n; }
static int same(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static void put(const char *s) { SC(SYS_write, 1, s, length(s)); }
static char *utoa(char *p, unsigned long v)
{
    char t[24]; int n = 0;
    do { t[n++] = '0' + v % 10; v /= 10; } while (v);
    while (n) *p++ = t[--n];
    return p;
}
static char *text(char *p, const char *s) { while (*s) *p++ = *s++; return p; }
static long number(const char *s)
{
    long v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return v;
}
static unsigned long octal(const char *s, int n)
{
    unsigned long v = 0;
    while (n > 0 && *s == ' ') { ++s; --n; }
    while (n > 0 && *s >= '0' && *s <= '7') { v = v * 8 + (*s++ - '0'); --n; }
    return v;
}

static void report(const char *name, long passes, long ns, long ops, long extra, const char *extra_name)
{
    char line[256], *p = line;
    p = text(p, "RESULT class="); p = text(p, name);
    p = text(p, " passes="); p = utoa(p, passes);
    p = text(p, " ns="); p = utoa(p, ns);
    p = text(p, " ops="); p = utoa(p, ops);
    if (extra_name) { *p++ = ' '; p = text(p, extra_name); *p++ = '='; p = utoa(p, extra); }
    *p++ = '\n'; *p = 0;
    SC(SYS_write, 1, line, p - line);
}

/* ---- setup of owned storage (never timed) ------------------------------ */
static int fill_owned(void)
{
    for (int i = 0; i < 4096; ++i) buffer[i] = (char)(i * 7);
    long fd = SC(SYS_open, "/work/one", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || SC(SYS_write, fd, buffer, 4096) != 4096) return 1;
    SC(SYS_close, fd, 0, 0);
    if (SC(SYS_mkdir, "/work/dir", 0700, 0) < 0) return 2;
    for (int i = 0; i < 64; ++i) {
        char path[64], *p = text(path, "/work/dir/f");
        p = utoa(p, i); *p = 0;
        fd = SC(SYS_open, path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) return 3;
        SC(SYS_write, fd, buffer, 64);
        SC(SYS_close, fd, 0, 0);
    }
    return 0;
}

/* ---- single-call and small-sequence classes ---------------------------- */
static long c_stat(const char *path, long n)
{
    long t = now();
    for (long i = 0; i < n; ++i) if (SC4(SYS_newfstatat, AT_FDCWD, path, st, 0) != 0) return -1;
    return now() - t;
}
static long c_statx(const char *path, long n)
{
    long t = now();
    for (long i = 0; i < n; ++i) if (SC5(SYS_statx, AT_FDCWD, path, 0, 0x7ff, stx) != 0) return -1;
    return now() - t;
}
static long c_openread(const char *path, long n)
{
    long t = now();
    for (long i = 0; i < n; ++i) {
        long fd = SC(SYS_open, path, 0, 0);
        if (fd < 0 || SC(SYS_read, fd, buffer, 4096) != 4096 || SC(SYS_close, fd, 0, 0) != 0) return -1;
    }
    return now() - t;
}
static long c_getdents(const char *path, long n)
{
    long t = now();
    for (long i = 0; i < n; ++i) {
        long fd = SC(SYS_open, path, O_DIRECTORY, 0), total = 0, got;
        if (fd < 0) return -1;
        while ((got = SC(SYS_getdents64, fd, dents, sizeof dents)) > 0) total += got;
        if (got < 0 || total == 0 || SC(SYS_close, fd, 0, 0) != 0) return -1;
    }
    return now() - t;
}
static long c_create(long n)
{
    /* Batches of 128 new files: create+write+close timed, unlink not. */
    long spent = 0, done = 0;
    if (SC(SYS_mkdir, "/work/new", 0700, 0) < 0) return -1;
    while (done < n) {
        long batch = n - done < 128 ? n - done : 128;
        long t = now();
        for (long i = 0; i < batch; ++i) {
            char path[48], *p = text(path, "/work/new/c"); p = utoa(p, i); *p = 0;
            long fd = SC(SYS_open, path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0 || SC(SYS_write, fd, buffer, 64) != 64 || SC(SYS_close, fd, 0, 0) != 0) return -1;
        }
        spent += now() - t;
        for (long i = 0; i < batch; ++i) {
            char path[48], *p = text(path, "/work/new/c"); p = utoa(p, i); *p = 0;
            SC(SYS_unlink, path, 0, 0);
        }
        done += batch;
    }
    return spent;
}
static long c_seekread(const char *path, long n)
{
    long fd = SC(SYS_open, path, 0, 0);
    if (fd < 0) return -1;
    long t = now();
    for (long i = 0; i < n; ++i)
        if (SC(SYS_lseek, fd, 100, 0) != 100 || SC4(SYS_pread64, fd, buffer, 64, 128) != 64) return -1;
    long spent = now() - t;
    SC(SYS_close, fd, 0, 0);
    return spent;
}
static long c_forkexec(long n)
{
    static char *argv[] = {"fixture", "noop", 0};
    static char *envp[] = {0};
    long t = now();
    for (long i = 0; i < n; ++i) {
        long pid = SC(SYS_fork, 0, 0, 0);
        if (pid < 0) return -1;
        if (pid == 0) {
            SC(SYS_execve, "/bin/fixture", argv, envp);
            SC(SYS_exit_group, 127, 0, 0);
        }
        int status = 1;
        if (SC4(SYS_wait4, pid, &status, 0, 0) != pid || status != 0) return -1;
    }
    return now() - t;
}
static long c_mmap(long n)
{
    long t = now();
    for (long i = 0; i < n; ++i) {
        long m = call(SYS_mmap, 0, 4096, 3, 0x22, (word)-1, 0);
        if (m < 0 && m > -4096) return -1;
        if (SC(SYS_munmap, m, 4096, 0) != 0) return -1;
    }
    return now() - t;
}
static long c_clock(long n)
{
    long t = now();
    for (long i = 0; i < n; ++i) SC(SYS_clock_gettime, 1, ts, 0);
    return now() - t;
}
static long c_getpid(long n)
{
    long t = now();
    for (long i = 0; i < n; ++i) SC(SYS_getpid, 0, 0, 0);
    return now() - t;
}

/* Two threads alternate through one futex word: 4 calls per round trip. */
static volatile int turn, finished;
static long thread_rounds;
static char thread_stack[65536] __attribute__((aligned(16)));
static void futex_wait_for(volatile int *word_, int expected_not)
{
    while (*word_ == expected_not) SC4(SYS_futex, word_, FUTEX_WAIT, expected_not, 0);
}
static void futex_wake_one(volatile int *word_) { SC(SYS_futex, word_, FUTEX_WAKE, 1); }
static void worker(void)
{
    for (long i = 0; i < thread_rounds; ++i) {
        while (turn != 1) SC4(SYS_futex, &turn, FUTEX_WAIT, 0, 0);
        turn = 0;
        futex_wake_one(&turn);
    }
    finished = 1;
    futex_wake_one(&finished);
}
static long c_futex(long n)
{
    thread_rounds = n; turn = 0; finished = 0;
    long r;
    register word r10 __asm__("r10") = 0;
    register word r8 __asm__("r8") = 0;
    __asm__ volatile(
        "syscall\n\t"
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"
        "xor %%ebp, %%ebp\n\t"
        "call *%%rbx\n\t"
        "mov $60, %%eax\n\t"
        "xor %%edi, %%edi\n\t"
        "syscall\n"
        "1:"
        : "=a"(r)
        : "0"((long)SYS_clone), "D"((word)0xd0f00), "S"((word)(thread_stack + sizeof thread_stack)),
          "d"((word)0), "r"(r10), "r"(r8), "b"((word)worker)
        : "rcx", "r11", "memory");
    if (r < 0) return -1;
    long t = now();
    for (long i = 0; i < n; ++i) {
        turn = 1;
        futex_wake_one(&turn);
        futex_wait_for(&turn, 1);
    }
    long spent = now() - t;
    futex_wait_for(&finished, 0);
    return spent;
}
static long c_pipe(long n)
{
    int a[2], b[2];
    char byte = 'x';
    if (SC(SYS_pipe, a, 0, 0) != 0 || SC(SYS_pipe, b, 0, 0) != 0) return -1;
    long pid = SC(SYS_fork, 0, 0, 0);
    if (pid < 0) return -1;
    if (pid == 0) {
        for (long i = 0; i < n; ++i) {
            if (SC(SYS_read, a[0], &byte, 1) != 1 || SC(SYS_write, b[1], &byte, 1) != 1)
                SC(SYS_exit_group, 1, 0, 0);
        }
        SC(SYS_exit_group, 0, 0, 0);
    }
    long t = now();
    for (long i = 0; i < n; ++i)
        if (SC(SYS_write, a[1], &byte, 1) != 1 || SC(SYS_read, b[0], &byte, 1) != 1) return -1;
    long spent = now() - t;
    int status = 1;
    SC4(SYS_wait4, pid, &status, 0, 0);
    SC(SYS_close, a[0], 0, 0); SC(SYS_close, a[1], 0, 0);
    SC(SYS_close, b[0], 0, 0); SC(SYS_close, b[1], 0, 0);
    return status == 0 ? spent : -1;
}

/* ---- build-shaped workloads -------------------------------------------- */
static long items, checksum;
static void walk(char *path, int hash)
{
    char block[8192] __attribute__((aligned(8)));
    unsigned long base = length(path);
    long fd = SC(SYS_open, path, O_DIRECTORY, 0), got;
    if (fd < 0) { items = -1000000; return; }
    while ((got = SC(SYS_getdents64, fd, block, sizeof block)) > 0) {
        for (long off = 0; off < got;) {
            unsigned short reclen = *(unsigned short *)(block + off + 16);
            const char *name = block + off + 19;
            off += reclen;
            if (name[0] == '.' && (!name[1] || (name[1] == '.' && !name[2]))) continue;
            char *p = path + base; *p++ = '/'; p = text(p, name); *p = 0;
            if (SC4(SYS_newfstatat, AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW) != 0) { items = -1000000; continue; }
            unsigned mode = *(unsigned *)(st + 24);
            ++items;
            if ((mode & 0170000) == 0040000) walk(path, hash);
            else if (hash && (mode & 0170000) == 0100000) {
                long f = SC(SYS_open, path, 0, 0), r;
                if (f < 0) { items = -1000000; continue; }
                unsigned long h = 1469598103934665603UL;
                while ((r = SC(SYS_read, f, buffer, sizeof buffer)) > 0)
                    for (long i = 0; i < r; ++i) h = (h ^ (unsigned char)buffer[i]) * 1099511628211UL;
                SC(SYS_close, f, 0, 0);
                checksum ^= (long)h;
            }
            path[base] = 0;
        }
    }
    SC(SYS_close, fd, 0, 0);
}
static long w_walk(long passes, int hash)
{
    char path[1024];
    long t = now(), first = -1;
    for (long i = 0; i < passes; ++i) {
        items = 0; checksum = 0;
        text(path, "/img/tree")[0] = 0;
        walk(path, hash);
        if (items <= 0) return -1;
        if (first < 0) first = items; else if (items != first) return -1;
    }
    return now() - t;
}
static long w_tar(long passes)
{
    long t = now();
    for (long pass = 0; pass < passes; ++pass) {
        char root[32], *r = text(root, "/work/u"); r = utoa(r, pass); *r = 0;
        if (SC(SYS_mkdir, root, 0700, 0) < 0) return -1;
        long fd = SC(SYS_open, "/img/archive.tar", 0, 0), size = 0, got;
        if (fd < 0) return -1;
        while ((got = SC(SYS_read, fd, archive + size, sizeof archive - size)) > 0) size += got;
        SC(SYS_close, fd, 0, 0);
        items = 0;
        for (long off = 0; off + 512 <= size; ) {
            const char *h = archive + off;
            if (!h[0]) break;
            unsigned long bytes = octal(h + 124, 12), mode = octal(h + 100, 8);
            char kind = h[156], path[256], *p = text(path, root);
            *p++ = '/';
            for (int i = 0; i < 100 && h[i]; ++i) *p++ = h[i];
            if (p[-1] == '/') --p;
            *p = 0;
            off += 512;
            if (kind == '5') {
                if (SC(SYS_mkdir, path, mode, 0) < 0) return -1;
            } else if (kind == '0' || kind == 0) {
                long out = SC(SYS_open, path, O_WRONLY | O_CREAT | O_TRUNC, mode);
                if (out < 0 || SC(SYS_write, out, archive + off, bytes) != (long)bytes ||
                    SC(SYS_close, out, 0, 0) != 0) return -1;
                off += (bytes + 511) & ~511UL;
            }
            ++items;
        }
    }
    return now() - t;
}

long bench_main(word *stack)
{
    word argc = *stack;
    char **argv = (char **)(stack + 1);
    if (argc >= 2 && same(argv[1], "noop")) return 0;
    if (argc < 3) { put("usage: fixture <class> <passes>\n"); return 2; }
    const char *cls = argv[1];
    long n = number(argv[2]), spent = -1, ops = n;
    long extra = 0; const char *extra_name = 0;
    int needs_owned = same(cls, "stat_owned") || same(cls, "statx_owned") || same(cls, "openread_owned") ||
                      same(cls, "getdents_owned") || same(cls, "seekread_owned");
    if (needs_owned && fill_owned()) { put("owned setup failed\n"); return 3; }
    if (same(cls, "stat_image")) spent = c_stat("/img/one", n);
    else if (same(cls, "statx_image")) spent = c_statx("/img/one", n);
    else if (same(cls, "openread_image")) spent = c_openread("/img/one", n);
    else if (same(cls, "getdents_image")) spent = c_getdents("/img/dir", n);
    else if (same(cls, "stat_owned")) spent = c_stat("/work/one", n);
    else if (same(cls, "statx_owned")) spent = c_statx("/work/one", n);
    else if (same(cls, "openread_owned")) spent = c_openread("/work/one", n);
    else if (same(cls, "getdents_owned")) spent = c_getdents("/work/dir", n);
    else if (same(cls, "create_owned")) spent = c_create(n);
    else if (same(cls, "seekread_image")) spent = c_seekread("/img/one", n);
    else if (same(cls, "seekread_owned")) spent = c_seekread("/work/one", n);
    else if (same(cls, "fork_exec_wait")) spent = c_forkexec(n);
    else if (same(cls, "mmap_munmap")) spent = c_mmap(n);
    else if (same(cls, "clock_gettime")) spent = c_clock(n);
    else if (same(cls, "getpid")) spent = c_getpid(n);
    else if (same(cls, "futex_pair")) spent = c_futex(n);
    else if (same(cls, "pipe_pingpong")) spent = c_pipe(n);
    else if (same(cls, "walk_lstat") || same(cls, "hash_walk")) {
        spent = w_walk(n, same(cls, "hash_walk"));
        ops = n * items; extra = items; extra_name = "entries";
    } else if (same(cls, "tar_unpack")) {
        spent = w_tar(n);
        ops = n * items; extra = items; extra_name = "entries";
    } else { put("unknown class\n"); return 2; }
    if (spent < 0) { put("class failed\n"); return 4; }
    report(cls, n, spent, ops, extra, extra_name);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall bench_main\nmov %rax,%rdi\nmov $231,%rax\nsyscall\nud2\n");
