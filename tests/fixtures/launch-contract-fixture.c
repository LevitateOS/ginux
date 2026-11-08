/* Direct x86-64 workload calls for configured contract controls. */
typedef unsigned long word;
static long call(word n, word a, word b, word c, word d) {
    register word r10 __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return result;
}
static long number(const char *s) {
    long n = 0, sign = 1;
    if (*s == '-') { sign = -1; ++s; }
    while (*s) n = n * 10 + *s++ - '0';
    return n * sign;
}
long contract_main(word *stack) {
    if (stack[0] != 3) return 90;
    char **argv = (char **)(stack + 1);
    long result;
    char byte = 0;
    word data[32] = {0};
    switch (argv[1][0]) {
    case 'r': result = call(2, (word)"/input", 0, 0, 0); break;
    case 'w': result = call(2, (word)"/work/new", 0101, 0600, 0); break;
    case 'c': result = call(228, 1, (word)data, 0, 0); break;
    case 's': result = call(35, (word)data, 0, 0, 0); break;
    case 'm': result = call(12, 0, 0, 0, 0); break;
    case 'g': result = call(105, 0, 0, 0, 0); break;
    case 'i': result = call(14, 0, 0, 0, 8); break;
    case 'p': result = call(22, (word)data, 0, 0, 0); break;
    case 'n': result = call(41, 2, 1, 0, 0); break;
    case 'u': result = call(999, 0, 0, 0, 0); break;
    case 'f':
        result = call(57, 0, 0, 0, 0);
        if (result == 0) { call(60, 0, 0, 0, 0); return 91; }
        if (result > 0 && call(61, result, (word)data, 0, 0) < 0) return 92;
        break;
    case 'a': {
        long fd = call(32, 1, 0, 0, 0);
        if (fd < 0) return 93;
        result = call(1, fd, (word)"alias\n", 6, 0);
        break;
    }
    case 'b': {
        long fd = call(32, 0, 0, 0, 0);
        if (fd < 0) return 93;
        result = call(0, fd, (word)&byte, 1, 0);
        break;
    }
    default: return 94;
    }
    if (result >= 0) result = 0;
    return result == number(argv[2]) ? 0 : 95;
}
__asm__(".global _start\n_start:\nmov %rsp, %rdi\nand $-16, %rsp\ncall contract_main\nmov %rax, %rdi\nmov $60, %rax\nsyscall\n");
