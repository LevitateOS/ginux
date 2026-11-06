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
    if (argc > 1 && argv[1][0] == 's') {
        CHECK(DO(83,"/work/dir",0755,0)==0,166);
        CHECK(DO(88,"dir","/work/link",0)==0,167);
        CHECK(DO(84,"/work/link/",0,0)==-20 && DO(87,"/work/link/",0,0)==-20,199);
        CHECK(DO(82,"/work/link/","/work/moved",0)==-20 && DO(4,"/work/dir",meta,0)==0,200);
        CHECK(DO(83,"/work/new/",0755,0)==0 && DO(84,"/work/new/",0,0)==0,201);
        CHECK(DO(84,"/work/link/.",0,0)==-22 && DO(82,"/work/link/.","/work/moved",0)==-22,202);
        CHECK(DO(4,"/work/dir",meta,0)==0,203);
        CHECK(DO(2,"/work/link/file",0102,0600)==3 && DO(1,3,"data",4)==4 && DO(3,3,0,0)==0,168);
        CHECK(DO(2,"/work/dir/file",0,0)==3 && DO(0,3,output,4)==4 && output[0]=='d' && DO(3,3,0,0)==0,169);
        CHECK(DO(6,"/work/link",meta,0)==0 && (*(word *)(meta+24)&0170000)==0120000,170);
        CHECK(DO(4,"/work/link",meta,0)==0 && (*(word *)(meta+24)&0170000)==0040000,171);
        CHECK(DO(89,"/work/link",output,2)==2 && output[0]=='d' && output[1]=='i',172);
        CHECK(DO(2,"/work/link",0400000,0)==-40 && DO(2,"/work/link",0301,0600)==-17,173);
        CHECK(DO(88,"../link","/work/dir/chain",0)==0,174);
        CHECK(DO(2,"/work/dir/chain/../fresh",0101,0600)==3 && DO(3,3,0,0)==0,175);
        CHECK(DO(4,"/work/fresh",meta,0)==0 && DO(4,"/work/dir/fresh",meta,0)==-2,176);
        CHECK(DO(88,"/image","/work/image",0)==0 && DO(2,"/work/image",0,0)==3,177);
        CHECK(DO(0,3,output,9)==9 && output[0]=='i' && DO(3,3,0,0)==0,216);
        CHECK(DO(88,"/","/work/root",0)==0 && DO(2,"/work/root/escape",0101,0600)<0,178);
        CHECK(DO(2,"/work/root/../image",0,0)<0 && DO(2,"/work/link/../../image",0,0)==3 && DO(3,3,0,0)==0,179);
        CHECK(DO(2,"/work/dir",0200000,0)==3,180);
        CHECK(DO(266,"file",3,"relative")==0,181);
        CHECK(call(267,3,(word)"relative",(word)output,64,0,0)==4 && output[0]=='f',182);
        CHECK(call(262,3,(word)"relative",(word)meta,0x100,0,0)==0 && (*(word *)(meta+24)&0170000)==0120000,183);
        CHECK(DO(257,3,"relative",0)==4 && DO(0,4,output,4)==4 && output[0]=='d' && DO(3,4,0,0)==0,184);
        CHECK(DO(3,3,0,0)==0,185);
        CHECK(DO(82,"/work/link","/work/renamed",0)==0 && DO(87,"/work/renamed",0,0)==0,186);
        CHECK(DO(4,"/work/dir/file",meta,0)==0,187);
        CHECK(DO(88,"cycle","/work/cycle",0)==0 && DO(2,"/work/cycle",0,0)==-40,188);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'l') {
        for (word i=0;i<10000;++i) CHECK(DO(39,0,0,0)>0,164);
        CHECK(DO(1,1,"events: PASS\n",13)==13,165);
        return 0;
    }
    if (argc > 2 && argv[1][0] == 'r') {
        long fd=DO(2,"/work/checkpoint",0,0);
        CHECK(fd==3,153);
        word length=argv[2][0]=='f' ? 5 : 6;
        CHECK(DO(0,fd,output,sizeof output)==(long)length,154);
        for (word i=0;i<length;++i) CHECK(output[i]==argv[2][i],155);
        CHECK(DO(5,fd,meta,0)==0 && (*(word *)(meta+24)&0777)==0600,156);
        CHECK(DO(3,fd,0,0)==0,157);
        char path[128]="/work/";
        for (word i=6;i<126;++i) path[i]='a';
        path[126]=0;
        CHECK(DO(2,path,0,0)==3 && DO(0,3,output,4)==4 && output[0]=='l' && DO(3,3,0,0)==0,158);
        CHECK(DO(4,"/work/empty",meta,0)==0 && (*(word *)(meta+24)&0170000)==0040000,159);
        CHECK(DO(4,"/work/checkpoint",meta,0)==0 && *(word *)(meta+16)==2,210);
        word inode=*(word *)(meta+8);
        CHECK(DO(4,"/work/check-hardlink",meta,0)==0 && *(word *)(meta+8)==inode && *(word *)(meta+16)==2,211);
        CHECK(DO(2,"/work/checkpoint",01001,0600)==3 && DO(1,3,"changed",7)==7 && DO(3,3,0,0)==0,160);
        CHECK(DO(2,"/work/check-hardlink",0,0)==3 && DO(0,3,output,7)==7 && output[0]=='c' && DO(3,3,0,0)==0,212);
        CHECK(DO(89,"/work/check-link",output,sizeof output)==10 && output[0]=='c',189);
        CHECK(DO(2,"/work/check-link",0,0)==3 && DO(0,3,output,7)==7 && output[0]=='c' && DO(3,3,0,0)==0,190);
        CHECK(DO(89,"/work/long-link",output,sizeof output)==126 && output[0]=='/',191);
        CHECK(DO(2,"/work/long-link",0,0)==3 && DO(0,3,output,4)==4 && output[0]=='l' && DO(3,3,0,0)==0,192);
        CHECK(DO(89,"/work/absolute",output,sizeof output)==10 && output[0]=='/',193);
        CHECK(DO(1,1,"restored: PASS\n",15)==15,161);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'c') {
        long fd=DO(2,"/work/checkpoint",0102,0600);
        CHECK(fd==3 && DO(1,fd,"first",5)==5,148);
        CHECK(DO(83,"/work/empty",0700,0)==0,162);
        char path[128]="/work/";
        for (word i=6;i<126;++i) path[i]='a';
        path[126]=0;
        CHECK(DO(2,path,0101,0640)==4 && DO(1,4,"long",4)==4 && DO(3,4,0,0)==0,163);
        CHECK(DO(86,"/work/checkpoint","/work/check-hardlink",0)==0,213);
        CHECK(DO(86,path,"/work/long-hardlink",0)==0,214);
        CHECK(DO(88,"checkpoint","/work/check-link",0)==0,194);
        CHECK(DO(88,path,"/work/long-link",0)==0,195);
        CHECK(DO(88,"/usr/bin/x","/work/absolute",0)==0,196);
        CHECK(DO(1,1,"checkpoint-ready\n",17)==17 && DO(0,0,output,1)==1,149);
        CHECK(DO(8,fd,0,0)==0 && DO(1,fd,"second",6)==6,150);
        CHECK(DO(1,1,"checkpoint-ready\n",17)==17 && DO(0,0,output,1)==1,151);
        CHECK(DO(74,fd,0,0)==0 && DO(75,fd,0,0)==0,215);
        CHECK(DO(3,fd,0,0)==0,152);
        return 0;
    }
    if (argc > 1 && (argv[1][0] == 'e' || argv[1][0] == 'f')) {
        CHECK(DO(83,"/out/empty",0755,0)==0,143);
        long fd=DO(2,"/out/product",0101,0700);
        CHECK(fd==3 && DO(1,fd,"result\0data",11)==11 && DO(3,fd,0,0)==0,144);
        CHECK(DO(2,"/out/deleted",0101,0600)==3 && DO(3,3,0,0)==0 && DO(87,"/out/deleted",0,0)==0,145);
        char longpath[208]="/out/";
        for (word i=5;i<125;++i) longpath[i]='a';
        longpath[125]=0; CHECK(DO(83,longpath,0700,0)==0,146);
        longpath[125]='/';
        for (word i=126;i<206;++i) longpath[i]='b';
        longpath[206]=0;
        CHECK(DO(2,longpath,0101,0600)==3 && DO(1,3,"long",4)==4 && DO(3,3,0,0)==0,147);
        CHECK(DO(88,"product","/out/product-link",0)==0,197);
        CHECK(DO(88,longpath,"/out/long-link",0)==0,198);
        return argv[1][0]=='f' ? 7 : 0;
    }
    if (argc > 1 && argv[1][0] == 'm') {
        long fd=DO(2,"/work/mapped",0102,0600);
        CHECK(fd==3 && DO(77,fd,8192,0)==0,110);
        CHECK(DO(21,"/work/mapped",0,0)==0 && DO(21,"/work/mapped",6,0)==0,136);
        CHECK(DO(21,"/work/mapped",1,0)==-13 && DO(21,"/work/absent",0,0)==-2,137);
        CHECK(DO(269,-100,"/work/mapped",4)==0,138);
        CHECK(call(439,fd,(word)"",4,0x1000,0,0)==0,139);
        CHECK(call(439,-100,(word)"/work/mapped",0,0x300,0,0)==0,140);
        CHECK(DO(21,"/work/mapped",8,0)==-22 && call(439,-100,(word)"/work/mapped",0,0x8000,0,0)==-22,141);
        CHECK(DO(91,fd,0700,0)==0 && DO(21,"/work/mapped",1,0)==0,142);
        CHECK(DO(1,fd,"old",3)==3 && DO(8,fd,4096,0)==4096 && DO(1,fd,"second",6)==6,111);
        CHECK(call(9,0,8192,3,1,fd,0)==-95,112);
        long shared=call(9,0,4096,1,1,fd,0);
        CHECK(shared>0 && *(volatile char *)shared=='o',132);
        CHECK(DO(10,shared,4096,3)==-13 && DO(11,shared,4096,0)==0,133);
        CHECK(call(9,0,8192,3,2,fd,1)==-22,113);
        word stack_pointer; __asm__ volatile("mov %%rsp,%0":"=r"(stack_pointer));
        CHECK(call(9,(stack_pointer-16384)&~4095UL,32768,3,0x12,fd,0)==-95,134);
        long mapped=call(9,0,8192,3,2,fd,0);
        CHECK(mapped>0,114);
        volatile char *bytes=(volatile char *)mapped;
        CHECK(bytes[0]=='o' && bytes[4096]=='s' && bytes[8191]==0,115);
        CHECK(DO(8,fd,0,1)==4102,116);
        CHECK(DO(8,fd,0,0)==0 && DO(1,fd,"new",3)==3 && bytes[0]=='n',117);
        bytes[0]='C';
        CHECK(DO(8,fd,0,0)==0 && DO(0,fd,output,3)==3 && output[0]=='n',118);
        long child=DO(57,0,0,0);
        CHECK(child>=0,119);
        if (!child) {
            CHECK(DO(8,fd,4096,0)==4096 && DO(1,fd,"fresh",5)==5,120);
            DO(60,0,0,0); __builtin_unreachable();
        }
        int status;
        CHECK(DO(61,child,&status,0)==child && status==0 && bytes[4096]=='f',121);
        child=DO(57,0,0,0);
        CHECK(child>=0,122);
        if (!child) {
            CHECK(DO(77,fd,0,0)==0,123);
            volatile char fault=bytes[4096]; (void)fault;
            DO(60,99,0,0); __builtin_unreachable();
        }
        CHECK(DO(61,child,&status,0)==child && (status&127)==7,124);
        CHECK(DO(77,fd,8192,0)==0 && bytes[4096]==0,125);
        CHECK(DO(11,mapped,8192,0)==0,126);
        CHECK(DO(8,fd,0,0)==0 && DO(1,fd,"kept",4)==4,127);
        mapped=call(9,0,4096,1,2,fd,0); CHECK(mapped>0,128);
        CHECK(DO(87,"/work/mapped",0,0)==0 && DO(3,fd,0,0)==0,129);
        fd=DO(2,"/work/mapped",0102,0600);
        CHECK(fd==3 && DO(1,fd,"other",5)==5 && *(volatile char *)mapped=='k',130);
        CHECK(DO(11,mapped,4096,0)==0 && DO(3,fd,0,0)==0,131);
        CHECK(DO(1,1,"mapping-ready\n",14)==14 && DO(0,0,output,1)==1 && output[0]=='G',135);
        return 0;
    }
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
            if (fd == -28) return i == 8189 ? 0 : 61;
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
        CHECK(DO(86,"/out/d","/out/shared",0)==0 && DO(5,d,meta,0)==0 && *(word *)(meta+16)==2,131);
        long shared=DO(2,"/out/shared",0,0); CHECK(shared>=3,132);
        CHECK(DO(5,shared,meta,0)==0 && *(word *)(meta+48)==16*mib && DO(3,shared,0,0)==0,133);
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
