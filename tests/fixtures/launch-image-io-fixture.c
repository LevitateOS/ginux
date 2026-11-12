/* Configured image I/O, virtual statfs, child-only virtual credentials and
   legacy stat/lstat as their newfstatat form. */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e, word f)
{
    register word r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(condition,code) if (!(condition)) return code
static unsigned char buffer[2*1024*1024+32];
static word info[15];
static long system_view(int denied) {
    unsigned char view[128];
    for (unsigned i=0;i<sizeof view;++i) view[i]=0xa5;
    long result=DO(99,view+8,0,0);
    CHECK(result==(denied ? -1 : 0),50);
    for (unsigned i=0;i<sizeof view;++i)
        CHECK(view[i]==(!denied && i>=8 && i<120 ? 0 : 0xa5),51);
    return 0;
}
/* x86-64 stat(4) and lstat(6) are newfstatat(AT_FDCWD, path, buf, 0) and
   newfstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW), as musl issues them. */
#define AT ((word)-100)
#define NOFOLLOW 0x100
static unsigned char legacy[144] __attribute__((aligned(8)));
static unsigned char at[144] __attribute__((aligned(8)));
static unsigned mode_of(const unsigned char *st) { return *(const unsigned *)(st+24) & 0170000; }
static int same(long a, long b)
{
    if (a!=b) return 0;
    for (unsigned i=0;i<sizeof legacy;++i) if (legacy[i]!=at[i]) return 0;
    return 1;
}
static void fill(void)
{
    for (unsigned i=0;i<sizeof legacy;++i) { legacy[i]=0xa5; at[i]=0xa5; }
}
/* Both forms return the same result and the same bytes for this path. */
static int parity(const char *path)
{
    fill();
    long a=DO(4,path,legacy,0), b=call(262,AT,(word)path,(word)at,0,0,0);
    if (!same(a,b)) return 0;
    fill();
    a=DO(6,path,legacy,0); b=call(262,AT,(word)path,(word)at,NOFOLLOW,0,0);
    return same(a,b);
}
/* The kernel ABI preserves every argument register across a syscall. */
static int preserved(long n, const char *path)
{
    register word r10 __asm__("r10")=0x1010, r8 __asm__("r8")=0x0808, r9 __asm__("r9")=0x0909;
    word rdi=(word)path, rsi=(word)legacy, rdx=0x0d0d;
    long result=n;
    __asm__ volatile("syscall":"+a"(result),"+D"(rdi),"+S"(rsi),"+d"(rdx),"+r"(r10),"+r"(r8),"+r"(r9)::"rcx","r11","memory");
    return result==0 && rdi==(word)path && rsi==(word)legacy && rdx==0x0d0d
        && r10==0x1010 && r8==0x0808 && r9==0x0909;
}
static long legacy_stat(void)
{
    long fd=DO(2,"/work/file",0102,0600); CHECK(fd>=3 && DO(3,fd,0,0)==0,60);
    CHECK(DO(83,"/work/dir",0755,0)==0,61);
    CHECK(DO(88,"file","/work/link",0)==0 && DO(88,"missing","/work/dangling",0)==0,62);
    static const char *paths[]={
        "/image","/image-dir","/image-link","/image-dangling","image-link","/bin/../image",
        "/missing","/image/child","/work/file","/work/dir","/work/link","/work/dangling",
        "/work/missing","/dev/null","/dev","/dev/missing","/proc/self/maps",0};
    for (int i=0;paths[i];++i) CHECK(parity(paths[i]),63);
    /* stat follows a final symlink and lstat does not, in image and owned paths. */
    CHECK(DO(4,"/image-link",legacy,0)==0 && mode_of(legacy)==0100000,64);
    CHECK(DO(6,"/image-link",legacy,0)==0 && mode_of(legacy)==0120000,65);
    CHECK(DO(4,"/work/link",legacy,0)==0 && mode_of(legacy)==0100000,66);
    CHECK(DO(6,"/work/link",legacy,0)==0 && mode_of(legacy)==0120000,67);
    CHECK(DO(4,"/image-dir",legacy,0)==0 && mode_of(legacy)==0040000,68);
    CHECK(DO(6,"/work/dir",legacy,0)==0 && mode_of(legacy)==0040000,69);
    CHECK(DO(6,"/dev/null",legacy,0)==0 && mode_of(legacy)==0020000,70);
    CHECK(DO(4,"/image-dangling",legacy,0)==-2 && DO(6,"/image-dangling",legacy,0)==0,71);
    CHECK(DO(4,"/work/dangling",legacy,0)==-2 && DO(6,"/work/dangling",legacy,0)==0,72);
    /* Missing paths and non-directory components. */
    CHECK(DO(4,"/missing",legacy,0)==-2 && DO(6,"/missing",legacy,0)==-2,73);
    CHECK(DO(4,"/work/missing",legacy,0)==-2 && DO(6,"/dev/missing",legacy,0)==-2,74);
    CHECK(DO(4,"/image/child",legacy,0)==-20 && DO(6,"/image/child",legacy,0)==-20,75);
    CHECK(DO(4,"",legacy,0)==-2 && DO(6,"",legacy,0)==-2,76);
    /* Faulting path and buffer addresses, as newfstatat reports them. */
    for (int n=4;n<=6;n+=2) {
        CHECK(DO(n,0,legacy,0)==-14 && DO(n,1,legacy,0)==-14,77);
        CHECK(call(262,AT,1,(word)at,n==6?NOFOLLOW:0,0,0)==-14,78);
        static const char *targets[]={"/image","/image-dir","/work/file","/dev/null","/proc/self/maps",0};
        for (int i=0;targets[i];++i) {
            CHECK(DO(n,targets[i],1,0)==-14,79);
            CHECK(call(262,AT,(word)targets[i],1,n==6?NOFOLLOW:0,0,0)==-14,80);
        }
        /* Registers return unchanged whichever backend answers. */
        CHECK(preserved(n,"/image") && preserved(n,"/image-link") && preserved(n,"/work/file"),81);
        CHECK(preserved(n,"/dev/null") && preserved(n,"/proc/self/maps"),82);
    }
    /* The image stays read-only. */
    CHECK(DO(87,"/image",0,0)<0 && DO(2,"/image",1,0)<0,83);
    DO(1,1,"legacy-stat: PASS\n",18);
    return 0;
}
/* The contract decides each legacy call by its own operation. */
static long legacy_stat_policy(void)
{
    CHECK(DO(6,"/image",legacy,0)==-1 && DO(6,"/work",legacy,0)==-1,90);
    CHECK(DO(4,"/image",legacy,0)==0 && call(262,AT,(word)"/image",(word)at,NOFOLLOW,0,0)==0,91);
    DO(1,1,"legacy-stat-policy: PASS\n",25);
    return 0;
}
long image_io_main(word *stack)
{
    char scenario=stack[0]>1 ? ((char *)stack[2])[0] : 0;
    if (scenario=='L') return legacy_stat();
    if (scenario=='P') return legacy_stat_policy();
    int denied=stack[0]>1 && ((char *)stack[2])[0]=='D';
    long system_result=system_view(denied);
    if (system_result) return system_result;
    if (stack[0]>1 && (denied || ((char *)stack[2])[0]=='S')) return 0;
    if(stack[0]>1) {
        CHECK(DO(102,0,0,0)==12345 && DO(107,0,0,0)==12345,30);
        CHECK(DO(104,0,0,0)==23456 && DO(108,0,0,0)==23456,31);
        CHECK(DO(105,0,0,0)==-1 && DO(106,0,0,0)==-1,32);
        CHECK(DO(1,1,"drop-ready\n",11)==11,33);
        CHECK(DO(0,0,buffer,1)==1 && buffer[0]=='G',34);
        return 0;
    }
    long fd=DO(2,"/image",0,0); CHECK(fd>=3,1);
    /* Pointer arguments must not be mistaken for internal network handles,
       including a 64-bit address whose low word aliases the handle range. */
    for (word address=0x60000000; address<=0x160000000; address+=0x100000000) {
        CHECK(call(9,address,4096,3,0x100022,-1,0)==(long)address,40);
        CHECK(DO(10,address,4096,1)==0,41);
        CHECK(DO(11,address,4096,0)==0,42);
        CHECK(call(9,address,4096,1,0x100002,fd,0)==(long)address,43);
        CHECK(*(unsigned char *)address=='Q',44);
        CHECK(DO(11,address,4096,0)==0,45);
    }
    CHECK(DO(0,fd,buffer,2*1024*1024)==2*1024*1024,2);
    CHECK(buffer[0]=='Q' && buffer[2*1024*1024-1]=='Q',3);
    CHECK(call(17,fd,(word)buffer,2*1024*1024,16,0,0)==2*1024*1024,4);
    CHECK(buffer[0]=='Q' && buffer[2*1024*1024-1]=='Q',5);
    CHECK(DO(137,"/image",info,0)==0 && info[0]==0x01021994 && info[10]==1,6);
    CHECK(DO(138,fd,info,0)==0 && info[10]==1 && info[7]==0,7);
    CHECK(DO(137,"/missing",info,0)==-2,8);
    CHECK(DO(137,"/image",1,0)==-14 && DO(138,fd,1,0)==-14,9);
    CHECK(DO(138,12345,info,0)==-9,10);
    CHECK(DO(137,"/work",info,0)==0 && info[10]==0 && info[2]>0,11);
    long owned=DO(2,"/work/file",0102,0600); CHECK(owned>=3,12);
    CHECK(DO(138,owned,info,0)==0 && info[10]==0 && info[7]==0,13);
    CHECK(DO(3,owned,0,0)==0 && DO(3,fd,0,0)==0,14);
    long child=DO(57,0,0,0); CHECK(child>=0,15);
    if(!child) {
        CHECK(DO(116,33,0,0)==-22 && DO(116,1,1,0)==-14,16);
        CHECK(DO(116,0,0,0)==0,17);
        CHECK(DO(106,23456,0,0)==0 && DO(105,12345,0,0)==0,18);
        CHECK(DO(116,0,0,0)==-1,19);
        char *argv[]={"/bin/fixture","after-drop",0}, *env[]={0};
        DO(59,argv[0],argv,env); return 20;
    }
    int status=-1; CHECK(DO(61,child,&status,0)==child && status==0,21);
    CHECK(DO(102,0,0,0)==0 && DO(104,0,0,0)==0,22);
    DO(1,1,"image-io: PASS\n",15);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall image_io_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
