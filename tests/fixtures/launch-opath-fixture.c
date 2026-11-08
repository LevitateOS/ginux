/* Metadata-only references, with a native oracle for the common Linux subset. */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e, word f)
{
    register word r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(expr,code) if (!(expr)) return code
#define PATH 010000000
#define CLO 02000000
static char meta[512] __attribute__((aligned(8))), bytes[128];
static word parse(const char *s) { word n=0; while(*s) n=n*10+(word)(*s++-'0'); return n; }
static void number(char *s,word n) { char b[24];unsigned i=0,j=0;do {b[i++]=(char)('0'+n%10);n/=10;}while(n);while(i)s[j++]=b[--i];s[j]=0; }
static int name(word fd,const char *want)
{
    char p[64]="/proc/self/fd/";number(p+14,fd);long n=DO(89,p,bytes,sizeof bytes);
    unsigned i=0;while(want[i]) {if(i>=(unsigned)n || bytes[i]!=want[i])return 0;++i;}return n==(long)i;
}
static int data_denied(word fd)
{
    struct {word base,size;} v={(word)bytes,1};
    if(DO(0,fd,bytes,1)!=-9 || DO(1,fd,"x",1)!=-9 || DO(8,fd,0,0)!=-9)return 0;
    if(DO(19,fd,&v,1)!=-9 || DO(20,fd,&v,1)!=-9)return 0;
    if(call(17,fd,(word)bytes,1,0,0,0)!=-9 || call(18,fd,(word)"x",1,0,0,0)!=-9)return 0;
    if(call(9,0,4096,1,2,fd,0)!=-9 || DO(217,fd,bytes,sizeof bytes)!=-9)return 0;
    return DO(77,fd,0,0)==-9 && DO(91,fd,0777,0)==-9 && DO(72,fd,4,0)==-9;
}
long opath_main(word *stack)
{
    char **args=(char **)(stack+1);char mode=*stack>1 ? args[1][0] : 'c';
    if(mode=='x') {
        long keep=(long)parse(args[2]),drop=(long)parse(args[3]);
        CHECK(DO(5,keep,meta,0)==0 && data_denied((word)keep),1);
        CHECK(DO(5,drop,meta,0)==-9,2);
        DO(1,1,"opath: PASS\n",12);return 0;
    }
    if(mode=='d') { for(unsigned i=0;i<260;++i)CHECK(DO(2,"/image/item",PATH,0)==-1,3);DO(1,1,"opath: PASS\n",12);return 0; }
    if(mode=='l') {
        for(word i=3;i<8;++i)CHECK(DO(2,"/image/item",PATH,0)==(long)i,4);
        CHECK(DO(2,"/image/item",PATH,0)==-24,5);
        for(word i=3;i<8;++i)CHECK(DO(3,i,0,0)==0,6);
        CHECK(DO(2,"/image/item",PATH,0)==3 && DO(3,3,0,0)==0,7);
        DO(1,1,"opath: PASS\n",12);return 0;
    }
    long image=DO(2,"/image/sealed",PATH|CLO|0100000,0);CHECK(image>=3,8);
    CHECK(DO(5,image,meta,0)==0 && *(word *)(meta+48)==7,9);
    CHECK(DO(72,image,3,0)==PATH && DO(72,image,1,0)==1,10);
    CHECK(data_denied((word)image),11);
    CHECK(DO(5,image,1,0)==-14 && DO(5,image,meta,0)==0,44);
    long image_dir=DO(2,"/image",PATH|0200000,0);CHECK(image_dir>=3,45);
    CHECK(call(262,(word)image_dir,(word)"item",(word)meta,0,0,0)==0,46);
    CHECK(DO(72,image_dir,3,0)==(PATH|0200000) && DO(3,image_dir,0,0)==0,47);
    CHECK(DO(83,"/work/directory",0755,0)==0,12);
    long ordinary=DO(2,"/work/directory/item",0102,0644);CHECK(ordinary>=3,13);
    CHECK(DO(1,ordinary,"payload",7)==7 && DO(3,ordinary,0,0)==0,14);
    CHECK(DO(88,"directory/item","/work/link",0)==0,15);
    long owned=DO(2,"/work/link",PATH,0);CHECK(owned>=3,16);
    CHECK(DO(5,owned,meta,0)==0 && *(word *)(meta+48)==7 && data_denied((word)owned),17);
    long directory=DO(2,"/work/directory",PATH|0200000,0);CHECK(directory>=3,18);
    CHECK(call(262,(word)directory,(word)"item",(word)meta,0,0,0)==0,19);
    CHECK(call(262,(word)owned,(word)"",(word)meta,0x1000,0,0)==0,20);
    CHECK(call(332,(word)directory,(word)"item",0,0x7ff,(word)meta,0)==0,21);
    CHECK(DO(267,directory,"item",bytes)==-22,22); /* zero readlink size */
    CHECK(DO(88,"item","/work/directory/link",0)==0,48);
    CHECK(call(267,(word)directory,(word)"link",(word)bytes,sizeof bytes,0,0)==4 && bytes[0]=='i',49);
    struct {int fd;short events,revents;} pollfd={(int)owned,1,0};
    CHECK(DO(7,&pollfd,1,0)==1 && pollfd.revents==32,50);
    CHECK(name((word)owned,"/work/directory/item") && name((word)image,"/image/sealed"),23);
    long alias=DO(32,owned,0,0);CHECK(alias>=3 && DO(72,alias,1,0)==0,24);
    CHECK(DO(33,owned,alias,0)==alias && DO(3,owned,0,0)==0 && data_denied((word)alias),25);
    if(mode!='n') {
        CHECK(call(257,(word)directory,(word)"item",0,0,0,0)==-9,26);
        CHECK(call(258,(word)directory,(word)"new",0755,0,0,0)==-9,27);
        CHECK(call(263,(word)directory,(word)"item",0,0,0,0)==-9,28);
        CHECK(call(268,(word)directory,(word)"item",0600,0,0,0)==-38,29); /* catalog denial precedes FD handling */
        CHECK(DO(81,directory,0,0)==-9,30);
        char p[64]="/dev/fd/";number(p+8,(word)alias);CHECK(DO(2,p,0,0)==-9,31);
        char *av[]={"fixture",0},*ev[]={0};
        CHECK(call(322,(word)image,(word)"",(word)av,(word)ev,0x1000,0)==-9,32);
        CHECK(call(322,(word)directory,(word)"item",(word)av,(word)ev,0,0)==-9,33);
        CHECK(DO(2,"/work/directory/item",PATH|01000,0)==-95,34);
        CHECK(DO(2,"/work/link",PATH|0400000,0)==-95,35);
        CHECK(DO(5,alias,meta,0)==0 && *(word *)(meta+48)==7,36);
    }
    long child=DO(57,0,0,0);CHECK(child>=0,37);
    if(!child) {CHECK(data_denied((word)alias) && DO(5,alias,meta,0)==0,38);return 0;}
    int status=-1;CHECK(call(61,(word)child,(word)&status,0,0,0,0)==child && status==0,39);
    CHECK(DO(3,directory,0,0)==0 && DO(3,alias,0,0)==0,40);
    for(word i=0;i<80;++i) {long fd=DO(2,"/work/directory/item",PATH,0);CHECK(fd>=3 && DO(3,fd,0,0)==0,41);}
    long keep=DO(2,"/work/directory/item",PATH,0);CHECK(keep>=3,42);
    static char a[24],b[24];number(a,(word)keep);number(b,(word)image);
    char *next[]={"fixture","x",a,b,0},*env[]={0};DO(59,"/bin/fixture",next,env);return 43;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall opath_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
