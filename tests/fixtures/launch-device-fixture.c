/* Real configured-launch null-device checks, without libc or host devices. */
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
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(expr,code) if (!(expr)) return code
static char meta[256] __attribute__((aligned(8)));
static const char immutable[] = "do not write into this";
long device_main(word *stack)
{
    word argc = *stack;
    char **argv = (char **)(stack + 1);
    CHECK(call(262,-100,(word)"",(word)meta,0x1000,0,0) == 0, 69);
    CHECK(DO(4,"/dev",meta,0) == 0, 10);
    CHECK((*(unsigned int *)(meta+24) & 0170000) == 0040000, 11);
    if (argc > 1 && argv[1][0] == 'n') {
        CHECK(DO(2,"/dev/null",0,0) == -2, 12);
        CHECK(DO(4,"/dev/null",meta,0) == -2, 13);
        CHECK(DO(2,"/dev/image-device",0,0) == -2, 14);
        CHECK(DO(2,"/alias-null",0,0) == -2, 55);
        CHECK(DO(4,"/alias-dev/image-device",meta,0) == -2, 56);
        return 0;
    }
    CHECK(DO(2,"/dev/image-device",0,0) == -2, 15);
    CHECK(DO(2,"/alias-dev/image-device",0,0) == -2, 57);
    CHECK(DO(2,"/dev/null/../null",0,0) == -20, 58);
    CHECK(DO(2,"/dev/missing/../null",0,0) == -2, 59);
    long alias = DO(2,"/alias-null",2,0);
    CHECK(alias >= 3, 60);
    CHECK(DO(5,alias,meta,0) == 0, 61);
    CHECK((*(unsigned int *)(meta+24) & 0170000) == 0020000, 62);
    CHECK(call(262,alias,(word)"",(word)meta,0x1900,0,0) == 0, 63);
    CHECK(call(332,-100,(word)"/alias-null",0x2900,0x7ff,(word)meta,0) == 0, 64);
    CHECK(call(332,alias,(word)"",0x5900,0x7ff,(word)meta,0) == 0, 65);
    CHECK(call(332,alias,(word)"",0x1000,0x80000000,(word)meta,0) == -22, 66);
    CHECK(call(332,-100,(word)"/dev/null",0x6000,0x7ff,(word)meta,0) == -22, 67);
    CHECK(DO(3,alias,0,0) == 0, 68);
    CHECK(DO(2,"/dev/null",0300,0644) == -17, 16);
    long fd = DO(2,"/dev/null",2|02000000,0);
    CHECK(fd == 3, 17);
    CHECK(DO(0,fd,1,4096) == 0, 70);
    CHECK(DO(1,fd,1,5000) == 4096, 71);
    CHECK(DO(0,fd,immutable,10) == 0, 18);
    CHECK(DO(1,fd,immutable,10) == 10, 19);
    CHECK(DO(8,fd,123,0) == 0, 20);
    CHECK(DO(72,fd,1,0) == 1, 21);
    CHECK(DO(72,fd,2,0) == 0, 22);
    CHECK(DO(72,fd,1,0) == 0, 23);
    CHECK((DO(72,fd,3,0) & 3) == 2, 24);
    CHECK(DO(16,fd,0,0) == -25, 25);
    CHECK(DO(5,fd,1,0) == -14, 26);
    CHECK(DO(5,fd,immutable,0) == -14, 27);
    CHECK(DO(5,fd,meta,0) == 0, 28);
    CHECK((*(unsigned int *)(meta+24) & 0170000) == 0020000, 29);
    CHECK(*(word *)(meta+40) == 0x103, 30);
    word inode = *(word *)(meta+8);
    CHECK(call(332,-100,(word)"/dev/null",0,0x7ff,(word)meta,0) == 0, 31);
    CHECK(*(unsigned int *)(meta+128) == 1 && *(unsigned int *)(meta+132) == 3, 32);
    CHECK(*(word *)(meta+32) == inode, 33);
    CHECK(call(262,fd,(word)"",(word)meta,0x1000,0,0) == 0, 34);
    CHECK(*(word *)(meta+8) == inode, 35);
    CHECK(call(439,fd,(word)"",4,0x1000,0,0) == 0, 72);
    CHECK(call(439,fd,(word)"",1,0x1000,0,0) == -13, 73);
    CHECK(DO(3,fd,0,0) == 0, 36);
    CHECK(DO(0,fd,meta,1) == -9, 37);
    long ro = DO(2,"/dev/null",0,0);
    CHECK(DO(1,ro,immutable,1) == -9, 38);
    CHECK(DO(3,ro,0,0) == 0, 39);
    long wo = call(257,-100,(word)"../dev/null",1,0,0,0);
    CHECK(wo >= 0, 40);
    CHECK(DO(0,wo,meta,1) == -9, 41);
    CHECK(DO(3,wo,0,0) == 0, 42);
    // Device-only configs must reserve the descriptor namespace too.
    word limits[2];
    CHECK(call(302,0,7,0,(word)limits,0,0) == 0, 43);
    CHECK(limits[1] <= 256, 44);
    long fds[64];
    for (word i=0;i<64;++i) {
        fds[i]=DO(2,"/dev/null",0,0);
        CHECK(fds[i] >= 3, 45);
    }
    CHECK(DO(2,"/dev/null",0,0) == -24, 46);
    for (word i=0;i<64;++i) CHECK(DO(3,fds[i],0,0) == 0, 47);
    CHECK(DO(21,"/dev/null",4,0) == 0, 48);
    CHECK(DO(21,"/dev/null",1,0) == -13, 49);
    CHECK(DO(87,"/dev/null",0,0) == -30, 50);
    CHECK(DO(4,"/dev/null",meta,0) == 0, 51);
    fd = DO(2,"/dev/null",01101,0644);
    CHECK(fd >= 3, 52);
    CHECK(DO(1,fd,immutable,10) == 10, 53);
    CHECK(DO(3,fd,0,0) == 0, 54);
    DO(1,1,"null-device: PASS\n",18);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall device_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
