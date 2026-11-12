/* Real configured-launch null and random device checks, without libc or host devices. */
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
static unsigned char first[128], second[128], large[5000], parts[2][8];
static int zeroed(const unsigned char *bytes, word length)
{
    for (word i = 0; i < length; ++i)
        if (bytes[i]) return 0;
    return 1;
}
static int same(const unsigned char *left, const unsigned char *right, word length)
{
    for (word i = 0; i < length; ++i)
        if (left[i] != right[i]) return 0;
    return 1;
}
/* /dev/random and /dev/urandom, as JavaScriptCore, OpenSSL and Python open them. */
static long random_main(int only_urandom)
{
    if (only_urandom) {
        CHECK(DO(2,"/dev/random",0,0) == -2, 140);
        CHECK(DO(2,"/dev/null",0,0) == -2, 141);
        long fd = DO(2,"/dev/urandom",0,0);
        CHECK(fd >= 3, 142);
        CHECK(DO(0,fd,first,128) == 128 && !zeroed(first,128), 143);
        CHECK(DO(3,fd,0,0) == 0, 144);
        DO(1,1,"urandom-device: PASS\n",21);
        return 0;
    }
    long random = DO(2,"/dev/random",02000000,0);
    long urandom = call(257,-100,(word)"/dev/urandom",2|04000,0,0,0);
    CHECK(random >= 3 && urandom >= 3 && random != urandom, 100);
    CHECK(DO(0,random,first,128) == 128, 101);
    CHECK(DO(0,urandom,second,128) == 128, 102);
    CHECK(!zeroed(first,128) && !zeroed(second,128), 103);
    CHECK(!same(first,second,128), 104);
    CHECK(DO(0,random,second,128) == 128 && !same(first,second,128), 105);
    CHECK(DO(0,urandom,large,5000) == 4096, 106);
    CHECK(!zeroed(large,4096) && zeroed(large+4096,904), 107);
    CHECK(DO(0,urandom,first,0) == 0, 108);
    CHECK(DO(0,urandom,1,16) == -14, 109);
    CHECK(DO(0,urandom,immutable,8) == -14, 110);
    CHECK(call(17,urandom,(word)first,16,0,0,0) == 16, 111);
    CHECK(call(17,urandom,(word)first,16,(word)-1,0,0) == -22, 112);
    word iov[4] = {(word)parts[0], 8, (word)parts[1], 8};
    CHECK(DO(19,random,iov,2) == 16, 113);
    CHECK(!zeroed(parts[0],8) && !zeroed(parts[1],8), 114);
    CHECK(DO(1,urandom,immutable,10) == 10, 115);
    CHECK(DO(1,urandom,1,10) == -14, 116);
    CHECK(DO(1,random,immutable,1) == -9, 117);
    CHECK(DO(20,urandom,iov,2) == 16, 118);
    CHECK(call(18,urandom,(word)immutable,4,0,0,0) == 4, 119);
    CHECK(DO(8,urandom,7,0) == 0, 120);
    CHECK((DO(72,urandom,3,0) & 04003) == 04002, 121);
    CHECK(DO(5,random,meta,0) == 0, 122);
    CHECK(*(unsigned int *)(meta+24) == 020666 && *(word *)(meta+40) == 0x108, 123);
    word random_inode = *(word *)(meta+8);
    CHECK(DO(4,"/dev/urandom",meta,0) == 0, 124);
    CHECK(*(unsigned int *)(meta+24) == 020666 && *(word *)(meta+40) == 0x109, 125);
    CHECK(*(word *)(meta+8) != random_inode, 126);
    CHECK(call(332,urandom,(word)"",0x1000,0x7ff,(word)meta,0) == 0, 127);
    CHECK(*(unsigned int *)(meta+128) == 1 && *(unsigned int *)(meta+132) == 9, 128);
    CHECK(DO(21,"/dev/urandom",6,0) == 0, 129);
    CHECK(DO(21,"/dev/random",1,0) == -13, 130);
    CHECK(DO(2,"/dev/random/../urandom",0,0) == -20, 131);
    struct { int fd; short events, revents; } polls[2] = {{(int)random, 5, 0}, {(int)urandom, 5, 0}};
    CHECK(DO(7,polls,2,0) == 2, 132);
    CHECK(polls[0].revents == 5 && polls[1].revents == 5, 133);
    unsigned int count = 0;
    CHECK(DO(16,random,0x80045200,&count) == 0 && count == 256, 134);
    CHECK(DO(16,random,0x80045200,immutable) == -14, 135);
    CHECK(DO(16,urandom,0x40045201,&count) == -1, 136);
    CHECK(DO(16,urandom,0x5207,0) == -1, 137);
    CHECK(DO(16,urandom,0x5401,meta) == -22, 138);
    CHECK(DO(87,"/dev/urandom",0,0) == -30, 139);
    long alias = DO(32,urandom,0,0);
    CHECK(alias >= 3 && DO(3,urandom,0,0) == 0, 145);
    CHECK(DO(0,alias,first,16) == 16, 146);
    CHECK(DO(3,alias,0,0) == 0 && DO(3,random,0,0) == 0, 147);
    CHECK(DO(0,random,first,1) == -9, 148);
    DO(1,1,"random-device: PASS\n",20);
    return 0;
}
long device_main(word *stack)
{
    word argc = *stack;
    char **argv = (char **)(stack + 1);
    CHECK(call(262,-100,(word)"",(word)meta,0x1000,0,0) == 0, 69);
    CHECK(DO(4,"/dev",meta,0) == 0, 10);
    CHECK((*(unsigned int *)(meta+24) & 0170000) == 0040000, 11);
    if (argc > 1 && (argv[1][0] == 'r' || argv[1][0] == 'u'))
        return random_main(argv[1][0] == 'u');
    CHECK(DO(2,"/dev/random",0,0) == -2, 74);
    CHECK(DO(4,"/dev/urandom",meta,0) == -2, 75);
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
