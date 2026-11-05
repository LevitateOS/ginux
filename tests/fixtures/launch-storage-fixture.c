/* Freestanding workload for real configured-launch memory-storage checks. */
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
static const char immutable[] = "readonly";
static char data[65536];
static char output[65536];
static char meta[256] __attribute__((aligned(8)));
long storage_main(word *stack)
{
    word argc = *stack;
    char **argv = (char **)(stack + 1);
    if (argc > 1 && argv[1][0] == 'n') {
        CHECK(DO(2, "/work/new", 0101, 0644) < 0, 10);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'q') {
        char path[] = "/out/file-0000";
        for (word i = 0; i < 9999; ++i) {
            path[10] = '0' + i / 1000;
            path[11] = '0' + i / 100 % 10;
            path[12] = '0' + i / 10 % 10;
            path[13] = '0' + i % 10;
            long fd = DO(2, path, 0101, 0644);
            if (fd == -28) return i == 4093 ? 0 : 61;
            CHECK(fd >= 3 && fd < 256, 62);
            CHECK(DO(3, fd, 0, 0) == 0, 63);
        }
        return 64;
    }
    if (argc > 1 && argv[1][0] == 'b') {
        const word mib=1024*1024;
        long a=DO(2,"/out/a",0102,0600), b=DO(2,"/out/b",0102,0600), c=DO(2,"/out/c",0102,0600);
        CHECK(a>=3 && b>=3 && c>=3,75);
        CHECK(DO(77,a,12*mib,0)==0 && DO(77,b,8*mib,0)==-28,76);
        CHECK(DO(5,b,meta,0)==0 && *(word *)(meta+48)==0,77);
        CHECK(DO(77,a,4*mib,0)==0 && DO(77,b,8*mib,0)==0,78);
        CHECK(DO(77,c,5*mib,0)==-28,79);
        CHECK(DO(3,a,0,0)==0 && DO(87,"/out/a",0,0)==0 && DO(77,c,5*mib,0)==0,80);
        CHECK(DO(87,"/out/b",0,0)==0 && DO(77,c,9*mib,0)==-28,81);
        CHECK(DO(3,b,0,0)==0 && DO(77,c,9*mib,0)==0,82);
        long alias=DO(32,c,0,0), d=DO(2,"/out/d",0102,0600);
        CHECK(alias>=3 && d>=3 && DO(87,"/out/c",0,0)==0,83);
        CHECK(DO(77,d,16*mib,0)==-28 && DO(3,c,0,0)==0 && DO(77,d,16*mib,0)==-28,84);
        CHECK(DO(3,alias,0,0)==0 && DO(77,d,16*mib,0)==0,85);
        CHECK(DO(8,d,16*mib-1,0)==16*mib-1 && DO(0,d,output,1)==1 && output[0]==0,86);
        CHECK(DO(1,d,"!",1)==-28 && DO(5,d,meta,0)==0 && *(word *)(meta+48)==16*mib,87);
        CHECK(DO(77,d,-1,0)==-22 && DO(5,d,meta,0)==0 && *(word *)(meta+48)==16*mib,88);
        return 0; // Teardown must release a still-linked full-quota mapping.
    }
    word limits[2];
    CHECK(call(302,0,7,0,(word)limits,0,0) == 0, 65);
    CHECK(limits[0] <= 1048576 && limits[1] <= 1048576, 66);
    limits[0] = limits[1] = 1048577;
    CHECK(call(302,0,7,(word)limits,0,0,0) < 0, 67);
    CHECK(DO(4, "/work", meta, 0) == 0, 11);
    CHECK((*(unsigned int *)(meta + 24) & 0170000) == 0040000, 12);
    CHECK(DO(2, "/work/existing", 0, 0) == -2, 13);
    CHECK(DO(2, "/image", 1, 0) < 0, 14);
    CHECK(DO(2, "/out/missing", 0, 0) == -2, 15);
    CHECK(DO(2, 1, 0, 0) == -14, 16);
    CHECK(DO(83, "/work/build/nested", 0755, 0) == 0, 17);
    long fd = call(257, -100, (word)"build/nested/file", 0102|0400|02000000, 0644, 0, 0);
    CHECK(fd == 3, 18);
    CHECK(DO(1, fd, "hello", 5) == 5, 19);
    CHECK(DO(89,"/work/build/nested/file",output,16)==-22,103);
    CHECK(call(267,-100,(word)"/work/build/nested/file",(word)output,16,0,0)==-22,104);
    CHECK(DO(89,"/work/build/nested/missing",output,16)==-2,105);
    CHECK(call(262,-100,(word)"/work/build/nested/file",(word)meta,0x900,0,0)==0,106);
    CHECK(call(332,-100,(word)"/work/build/nested/file",0x900,0x7ff,(word)meta,0)==0,107);
    CHECK(call(332,-100,(word)"/work/build/nested/file",0x6000,0x7ff,(word)meta,0)==-22,108);
    // O_NOCTTY must not reject regular files, including descriptor reopening.
    long reader = DO(2, "/work/build/nested/file", 0400, 0);
    CHECK(reader >= 3 && DO(0, reader, output, 5) == 5, 99);
    CHECK(output[0] == 'h' && DO(3, reader, 0, 0) == 0, 100);
    reader = DO(2, "/dev/fd/3", 0400, 0);
    CHECK(reader >= 3 && DO(0, reader, output, 5) == 5, 101);
    CHECK(output[4] == 'o' && DO(3, reader, 0, 0) == 0, 102);
    CHECK(DO(72, fd, 1, 0) == 1, 20);
    CHECK(DO(72, fd, 2, 0) == 0, 21);
    CHECK(DO(72, fd, 1, 0) == 0, 22);
    CHECK(DO(5, fd, meta, 0) == 0 && *(word *)(meta+48) == 5, 23);
    word inode = *(word *)(meta+8);
    CHECK(call(332,-100,(word)"/work/build/nested/file",0,0x7ff,(word)meta,0) == 0, 24);
    CHECK(*(word *)(meta+40) == 5 && *(word *)(meta+32) == inode, 25);
    CHECK(DO(8, fd, 0, 0) == 0, 26);
    CHECK(DO(0, fd, immutable, 5) == -14, 27);
    CHECK(DO(8, fd, 0, 1) == 0, 28);
    long pages = call(9,0,8192,3,0x22,-1,0);
    CHECK(pages > 0, 68);
    CHECK(DO(10, pages+4096, 4096, 0) == 0, 69);
    CHECK(DO(0, fd, pages+4094, 5) == 2, 70);
    CHECK(DO(8, fd, 0, 1) == 2, 71);
    CHECK(DO(0, fd, output, 3) == 3 && output[0] == 'l' && output[2] == 'o', 72);
    CHECK(DO(11, pages, 8192, 0) == 0, 73);
    CHECK(DO(8, fd, 0, 0) == 0, 74);
    CHECK(DO(0, fd, output, 5) == 5, 29);
    CHECK(output[0] == 'h' && output[4] == 'o', 30);
    CHECK(DO(1, fd, 1, 5) == -14, 31);
    CHECK(DO(5, fd, 1, 0) == -14, 32);
    CHECK(DO(0, fd, 1, 0) == 0, 33);
    CHECK(DO(3, 1048639, 0, 0) == -9, 34);
    CHECK(DO(2, "/work/build/nested/file", 0301, 0600) == -17, 35);
    CHECK(call(262,fd,(word)"",(word)meta,0x1000,0,0) == 0, 36);
    CHECK(*(word *)(meta+8) == inode, 37);
    CHECK(DO(87, "/work/build/nested/file", 0, 0) == 0, 38);
    CHECK(DO(4, "/work/build/nested/file", meta, 0) == -2, 39);
    CHECK(DO(8, fd, 0, 0) == 0, 40);
    CHECK(DO(0, fd, output, 5) == 5 && output[0] == 'h', 41);
    long replacement = DO(2, "/work/build/nested/file", 0102, 0600);
    CHECK(replacement > fd, 42);
    CHECK(DO(1, replacement, "other", 5) == 5, 43);
    CHECK(DO(5, replacement, meta, 0) == 0 && *(word *)(meta+8) != inode, 44);
    CHECK(DO(3, fd, 0, 0) == 0 && DO(3, replacement, 0, 0) == 0, 45);
    // Exhaustion must not truncate or mutate a file before open fails.
    long fds[64];
    for (word i = 0; i < 64; ++i) {
        fds[i] = DO(2, "/work/build/nested/file", 2, 0);
        CHECK(fds[i] >= 3 && fds[i] < 256, 46);
    }
    CHECK(DO(2, "/work/build/nested/file", 01002, 0) == -24, 47);
    CHECK(DO(5, fds[0], meta, 0) == 0 && *(word *)(meta+48) == 5, 48);
    for (word i = 0; i < 64; ++i) CHECK(DO(3, fds[i], 0, 0) == 0, 49);
    fd = DO(2, "/out/product", 0102, 0644);
    CHECK(fd >= 3 && fd < 256, 50);
    for (word i = 0; i < sizeof data; ++i) data[i] = i % 251;
    for (word i = 0; i < sizeof data; i += 4096) CHECK(DO(1, fd, data+i, 4096) == 4096, 51);
    CHECK(DO(1, fd, "x", 1) == 1, 52);
    CHECK(DO(8, fd, 0, 0) == 0, 53);
    for (word i = 0; i < sizeof output; i += 4096) CHECK(DO(0, fd, output+i, 4096) == 4096, 54);
    for (word i = 0; i < sizeof output; ++i) CHECK(output[i] == data[i], 55);
    CHECK(DO(0,fd,output,1)==1 && output[0]=='x',89);
    // Sparse growth and truncate/regrow must never reveal stale bytes.
    CHECK(DO(8,fd,2*1024*1024,0)==2*1024*1024 && DO(1,fd,"Q",1)==1,90);
    CHECK(DO(8,fd,2*1024*1024-1,0)==2*1024*1024-1,91);
    CHECK(DO(0,fd,output,2)==2 && output[0]==0 && output[1]=='Q',92);
    CHECK(DO(77,fd,3,0)==0 && DO(77,fd,8192,0)==0 && DO(8,fd,0,0)==0,93);
    CHECK(DO(0,fd,output,4096)==4096,94);
    CHECK(output[0]==data[0] && output[1]==data[1] && output[2]==data[2],95);
    for (word i=3;i<4096;++i) CHECK(output[i]==0,96);
    CHECK(DO(0,fd,output,4096)==4096,97);
    for (word i=0;i<4096;++i) CHECK(output[i]==0,98);
    CHECK(DO(91, fd, 0755, 0) == 0, 56);
    CHECK(DO(5, fd, meta, 0) == 0 && (*(unsigned int *)(meta+24) & 0777) == 0755, 57);
    CHECK(DO(3, fd, 0, 0) == 0, 58);
    CHECK(DO(87, "/out/product", 0, 0) == 0, 59);
    CHECK(DO(4, "/out/product", meta, 0) == -2, 60);
    DO(1, 1, "memory-storage: PASS\n", 21);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall storage_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
