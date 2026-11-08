/* Actual configured stack metadata, immutable public snapshot and lifetimes. */
typedef unsigned long word;
static long call(long n,word a,word b,word c,word d,word e,word f) {
    register word r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f; long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9) : "rcx","r11","memory"); return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(x,n) do { if(!(x)) return n; } while(0)
static char bytes[256], other[256];
static word statbuf[18], pathstat[18];
static const char readonly[256]={0};
static word hex(char **p) { word n=0;while((**p>='0'&&**p<='9')||(**p>='a'&&**p<='f')){char c=*(*p)++;n=n*16+(c<='9'?c-'0':c-'a'+10);}return n; }
long stack_main(word *stack) {
    char **argv=(char **)(stack+1);
    if(*stack>1 && argv[1][0]=='d') {
        CHECK(DO(2,"/proc/self/maps",0,0)==-1,10);
        CHECK(DO(4,"/proc/self/maps",statbuf,0)==-1,11);
        DO(1,1,"stack-deny: PASS\n",17); return 0;
    }
    if(*stack>1 && argv[1][0]=='x') {
        CHECK(DO(72,50,1,0)==0 && DO(72,51,1,0)==-9,12);
        CHECK(DO(0,50,bytes,sizeof bytes)>0,13);
        DO(1,1,"stack-exec: PASS\n",17); return 0;
    }
    CHECK(DO(21,"/proc/self/maps",4,0)==0 && DO(21,"/proc/self/maps",2,0)==-13,14);
    CHECK(DO(4,"/proc/self/maps",pathstat,0)==0 && (unsigned int)pathstat[3]==0100444,15);
    CHECK(DO(2,"/proc/self/maps",2,0)==-13 && DO(2,"/proc/self/maps",0100,0600)==-13,16);
    long fd=DO(2,"/proc/self/maps",0,0); CHECK(fd==3,17);
    CHECK(DO(5,fd,statbuf,0)==0 && statbuf[1]==pathstat[1] && (unsigned int)statbuf[3]==0100444,18);
    CHECK(DO(0,fd,readonly,sizeof readonly)==-14,19);
    long length=DO(0,fd,bytes,sizeof bytes); CHECK(length>40 && length<128,20);
    char *p=bytes; word low=hex(&p); CHECK(*p++=='-',21); word high=hex(&p);
    CHECK(low<(word)stack && (word)stack<high && *p==' ',22);
    CHECK(DO(0,fd,other,sizeof other)==0 && DO(8,fd,0,0)==0,23);
    long alias=DO(32,fd,0,0); CHECK(alias==4,24);
    CHECK(DO(0,alias,other,3)==3 && DO(8,fd,0,1)==3,25);
    CHECK(call(17,fd,(word)other,sizeof other,0,0,0)==length && DO(8,fd,0,1)==3,26);
    for(long i=0;i<length;++i) CHECK(bytes[i]==other[i],27);
    CHECK(DO(1,fd,"X",1)<0 && DO(91,fd,0600,0)==-30 && DO(77,fd,0,0)==-30,28);
    CHECK(call(9,0,4096,1,2,fd,0)==-95,29);
    CHECK(DO(2,"/proc/self/stat",0,0)<0 && DO(2,"/proc/1/maps",0,0)<0 && DO(2,"/proc/self",0200000,0)<0,30);
    CHECK(DO(3,alias,0,0)==0 && DO(3,fd,0,0)==0,31);
    // Repeated snapshots release both object data and bounded descriptor slots.
    for(int i=0;i<80;++i) { fd=DO(2,"/proc/self/maps",0,0);CHECK(fd==3 && DO(3,fd,0,0)==0,32); }
    fd=DO(2,"/proc/self/maps",0,0);CHECK(fd==3,33);
    int child=DO(57,0,0,0); CHECK(child>=0,34);
    if(child==0) { CHECK(DO(0,fd,other,sizeof other)==length,35);return 0; }
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0 && DO(8,fd,0,1)==length,36);
    CHECK(DO(8,fd,0,0)==0 && DO(33,fd,50,0)==50 && DO(292,fd,51,02000000)==51,37);
    DO(1,1,bytes,length);
    char *args[]={"/bin/fixture","x",0};DO(59,args[0],args,0);return 38;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall stack_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
