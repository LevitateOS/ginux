/* Configured self-FD names follow the caller's public descriptor owners. */
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
static char bytes[256], name[64];
static unsigned length(const char *s) { unsigned n=0; while(s[n]) ++n; return n; }
static unsigned number(char *out, word value)
{
    char digits[24]; unsigned n=0, i=0;
    do { digits[n++]=(char)('0'+value%10); value/=10; } while(value);
    while(n) { out[i++]=digits[--n]; }
    out[i]=0; return i;
}
static word parse(const char *s) { word n=0; while(*s) n=n*10+(word)(*s++-'0'); return n; }
static const char *path(word fd)
{
    const char *prefix="/proc/self/fd/"; unsigned i=0;
    while(prefix[i]) { name[i]=prefix[i]; ++i; }
    number(name+i,fd); return name;
}
static int points(word fd,const char *expected)
{
    unsigned n=length(expected);
    long got=DO(89,path(fd),bytes,sizeof bytes);
    if(got!=(long)n) return 0;
    for(unsigned i=0;i<n;++i) if(bytes[i]!=expected[i]) return 0;
    return 1;
}
long fd_path_main(word *stack)
{
    char **args=(char **)(stack+1);
    if(*stack>1 && args[1][0]=='x') {
        CHECK(points(parse(args[2]),"/work/moved"),40);
        CHECK(points(parse(args[3]),"/image/item"),41);
        CHECK(DO(89,path(parse(args[4])),bytes,sizeof bytes)==-2,42);
        DO(1,1,"fd-path: PASS\n",14); return 0;
    }
    long image=DO(2,"/image/item",0,0); CHECK(image>=3,1);
    if(*stack>1) {
        for(unsigned i=0;i<sizeof bytes;++i) bytes[i]='|';
        CHECK(DO(89,path((word)image),bytes,sizeof bytes)==-1,2);
        CHECK(call(267,(word)-77,(word)path((word)image),(word)bytes,sizeof bytes,0,0)==-1,3);
        for(unsigned i=0;i<sizeof bytes;++i) CHECK(bytes[i]=='|',4);
        static const char pass[]="fd-path-deny: PASS\n";
        DO(1,1,pass,sizeof pass-1); return 0;
    }
    CHECK(points((word)image,"/image/item"),5);
    long directory=DO(2,"/image",0200000,0); CHECK(directory>=3,6);
    CHECK(points((word)directory,"/image"),7);
    CHECK(DO(83,"/work/first",0755,0)==0,8);
    long owned=DO(2,"/work/first",0200000,0); CHECK(owned>=3,9);
    CHECK(points((word)owned,"/work/first"),10);
    long file=DO(2,"/work/first/item",0102,0600); CHECK(file>=3,11);
    CHECK(DO(1,file,"payload",7)==7 && points((word)file,"/work/first/item"),12);
    long alias=DO(32,file,0,0); CHECK(alias>=3 && DO(3,file,0,0)==0,13);
    CHECK(points((word)alias,"/work/first/item"),14);
    CHECK(DO(82,"/work/first","/work/moved",0)==0,15);
    CHECK(points((word)owned,"/work/moved") && points((word)alias,"/work/moved/item"),16);
    CHECK(DO(87,"/work/moved/item",0,0)==0,17);
    CHECK(DO(89,path((word)alias),bytes,sizeof bytes)==-2,18);
    CHECK(DO(8,alias,0,0)==0 && DO(0,alias,bytes,7)==7,19);
    CHECK(DO(89,"/proc/self/fd/256",bytes,sizeof bytes)==-2,20);
    CHECK(DO(89,"/proc/self/fd/4294967299",bytes,sizeof bytes)==-2,21);
    CHECK(DO(89,"/proc/self/fd/0",bytes,sizeof bytes)==-2,22);
    CHECK(DO(89,path((word)owned),bytes,0)==-22,23);
    for(unsigned i=0;i<sizeof bytes;++i) bytes[i]='|';
    CHECK(DO(89,path((word)owned),bytes,3)==3 && bytes[0]=='/' && bytes[1]=='w' && bytes[2]=='o' && bytes[3]=='|',24);
    CHECK(call(267,(word)-77,(word)path((word)owned),(word)bytes,sizeof bytes,0,0)==11,25);
    long child=DO(57,0,0,0); CHECK(child>=0,26);
    if(!child) { CHECK(points((word)owned,"/work/moved"),27); return 0; }
    int status=-1; CHECK(call(61,(word)child,(word)&status,0,0,0,0)==child && status==0,28);
    CHECK(points((word)owned,"/work/moved"),29);
    long dropped=DO(2,"/image/item",02000000,0); CHECK(dropped>=3,30);
    static char a[24],b[24],c[24]; number(a,(word)owned);number(b,(word)image);number(c,(word)dropped);
    char *next[]={"fixture","x",a,b,c,0}; char *env[]={0};
    DO(59,"/bin/fixture",next,env); return 31;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall fd_path_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
