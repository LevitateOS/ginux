/* Public descriptor namespace and cross-owner lifetime/register checks. */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e, word f)
{
    register word r10 __asm__("r10")=d;
    register word r8 __asm__("r8")=e;
    register word r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(expr,code) if (!(expr)) return code
static char bytes[256];
static char meta[256] __attribute__((aligned(8)));
long fd_main(word *stack)
{
    if (*stack>1 && ((char **)(stack+1))[1][0]=='r') {
        long fd=DO(2,"/work/read-policy",0102,0600);
        CHECK(fd==3 && DO(1,fd,"ok",2)==2,60);
        CHECK(DO(8,fd,0,0)==0,61);
        word alias=(1UL<<32)|(word)fd;
        struct { word base, length; } vector={(word)bytes,1};
        CHECK(DO(0,fd,bytes,1)==-1 && DO(0,alias,bytes,1)==-1,62);
        CHECK(DO(19,fd,&vector,1)==-1 && DO(19,alias,&vector,1)==-1,63);
        CHECK(DO(8,fd,0,1)==0 && DO(1,fd,"z",1)==1,64);
        CHECK(DO(3,alias,0,0)==0,65);
        static const char pass[]="contract-read: PASS\n";
        DO(1,1,pass,sizeof pass-1);
        return 0;
    }
    if (*stack>1 && ((char **)(stack+1))[1][0]=='w') {
        word limits[2]={3,256};
        CHECK(call(302,0,(1UL<<32)|7,(word)limits,0,0,0)==-1,49);
        CHECK(call(302,0,7,0,(word)limits,0,0)==0 && limits[0]==256 && limits[1]==256,50);
        DO(1,1,"resource-width: PASS\n",21);
        return 0;
    }
    if (*stack>1) {
        word limits[2];
        CHECK(call(302,0,7,0,(word)limits,0,0)==0 && limits[0]==8 && limits[1]==8,43);
        char path[]="/work/item-00";
        for(word n=0;n<20;++n) {
            path[11]='0'+n/10; path[12]='0'+n%10;
            long fd=DO(2,path,0102,0600); CHECK(fd==3,56);
            CHECK(DO(1,fd,"data",4)==4 && DO(3,fd,0,0)==0,57);
        }
        for(word i=3;i<8;++i) CHECK(DO(32,1,0,0)==(long)i,44);
        CHECK(DO(32,1,0,0)==-24,45);
        for(word i=3;i<8;++i) CHECK(DO(3,i,0,0)==0,46);
        DO(1,1,"lower-limit: PASS\n",18);
        return 0;
    }
    for (word i=0;i<260;++i) CHECK(DO(2,"/sealed",0,0)==-13,51);
    long translated=257;
    word directory=(word)-77, path=(word)"/work/../bin/fixture", flags=02000000;
    register word mode __asm__("r10")=0;
    __asm__ volatile("syscall":"+a"(translated),"+D"(directory),"+S"(path),"+d"(flags),"+r"(mode)::"rcx","r11","memory");
    CHECK(translated==3 && directory==(word)-77 && path==(word)"/work/../bin/fixture" && flags==02000000 && mode==0,52);
    CHECK(DO(72,translated,1,0)==1,53);
    CHECK(DO(3,translated,0,0)==0,54);
    long image=DO(2,"/bin/fixture",02000000,0);
    long null=DO(2,"/dev/null",2|02000000,0);
    long memory=DO(2,"/work/data",0102|02000000,0644);
    int pipe[2];
    CHECK(image==3 && null==4 && memory==5,10);
    CHECK(DO(293,pipe,02004000,0)==0 && pipe[0]==6 && pipe[1]==7,11);
    word limits[2];
    CHECK(call(302,0,7,0,(word)limits,0,0)==0 && limits[0]==256 && limits[1]==256,12);
    CHECK(DO(72,image,1,0)==1 && DO(72,null,1,0)==1 && DO(72,memory,1,0)==1,13);
    CHECK(DO(72,image,3,0)>=0 && DO(72,image,8,1234)==-1,47);
    CHECK(DO(1,memory,"ABC",3)==3 && DO(8,memory,0,0)==0,14);
    long alias=DO(32,memory,0,0);
    CHECK(alias==8 && DO(72,alias,1,0)==0,15);
    CHECK(DO(0,memory,bytes,1)==1 && bytes[0]=='A',16);
    CHECK(DO(0,alias,bytes,1)==1 && bytes[0]=='B',17); // Shared offset, including writable files.
    CHECK(DO(33,memory,image,0)==image,18); // Last native reference closes its private fd.
    CHECK(DO(0,image,bytes,1)==1 && bytes[0]=='C',19);
    long reopened=DO(2,"/bin/fixture",0,0);
    CHECK(reopened==9,20); // Native backend fd 3 is reused; public fd 3 still means memory.
    word argument=reopened;
    long count=0;
    __asm__ volatile("syscall":"+a"(count),"+D"(argument):"S"(bytes),"d"(4):"rcx","r11","memory");
    CHECK(count==4 && argument==(word)reopened && bytes[0]==127 && bytes[1]=='E',21);
    long mapped=call(9,0,4096,1,2,reopened,0);
    CHECK(mapped>0 && *(unsigned char *)mapped==127,22);
    CHECK(DO(11,mapped,4096,0)==0,23);
    mapped=call(9,0,4096,1,2,memory,0);
    CHECK(mapped>0 && *(unsigned char *)mapped=='A' && DO(11,mapped,4096,0)==0,24);
    CHECK(call(9,0,4096,3,1,memory,0)==-95,55); // Writable shared backing remains unsupported.
    CHECK(call(9,0,4096,1,2,0,0)==-95 && DO(217,0,bytes,sizeof bytes)==-20,48);
    CHECK(DO(33,null,reopened,0)==reopened,25);
    CHECK(DO(0,reopened,bytes,1)==0,26);
    CHECK(DO(3,null,0,0)==0 && DO(1,reopened,"discard",7)==7,27);
    CHECK(DO(3,alias,0,0)==0 && DO(3,memory,0,0)==0,28);
    CHECK(DO(8,image,0,0)==0 && DO(0,image,bytes,3)==3 && bytes[0]=='A',29);
    CHECK(DO(1,pipe[1],"pipe",4)==4 && DO(33,pipe[0],reopened,0)==reopened,30);
    CHECK(DO(3,pipe[0],0,0)==0 && DO(0,reopened,bytes,4)==4 && bytes[0]=='p',31);
    CHECK(DO(3,pipe[1],0,0)==0 && DO(0,reopened,bytes,1)==0,32);
    CHECK(DO(3,reopened,0,0)==0 && DO(3,image,0,0)==0,33);
    // Private backend numbers are not public authority.
    CHECK(DO(0,1048576,bytes,1)==-9 && DO(5,0x40000000,meta,0)==-9,34);
    CHECK(DO(3,(1UL<<32)|99,0,0)==-9,35);
    memory=DO(2,"/work/data",0,0);
    CHECK(memory==3,36);
    long aliases[252];
    for(word i=0;i<252;++i){ aliases[i]=DO(32,1,0,0);CHECK(aliases[i]>=0 && aliases[i]<256,37); }
    CHECK(DO(2,"/work/data",01001,0644)==-24,38); // No truncate on public-table exhaustion.
    CHECK(DO(2,"/bin/fixture",0,0)==-24,39);
    CHECK(DO(5,memory,meta,0)==0 && *(word *)(meta+48)==3,40);
    for(word i=0;i<252;++i) CHECK(DO(3,aliases[i],0,0)==0,41);
    CHECK(DO(3,(1UL<<32)|(word)memory,0,0)==0,42); // Linux fd arguments use the low 32 bits.
    DO(1,1,"shared-fds: PASS\n",17);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall fd_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
