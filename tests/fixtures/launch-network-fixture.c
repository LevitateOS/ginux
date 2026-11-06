/* Real configured TCP calls; the runner owns a bounded loopback server. */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e, word f)
{
    register word r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(x,c) if(!(x))return c
static char buffer[64];
static unsigned char address[16]={2,0,0,0,127,0,0,1};
long network_main(word *stack)
{
    char **argv=(char **)(stack+1); char mode=argv[1][0];
    unsigned port=0; for(char *p=argv[2];*p;++p)port=port*10+*p-'0';
    address[2]=port>>8; address[3]=port;
    if(mode=='o' && argv[1][1]=='f'){CHECK(DO(41,2,1,0)==-13,10);return 0;}
    long fd=DO(41,2,1|(mode=='n'?04000:0)|02000000,0); CHECK(fd>=3,11);
    CHECK(DO(72,fd,1,0)==1,12);
    if(mode=='s'){
        long second=DO(41,2,1,0);CHECK(second>=3 && DO(41,2,1,0)==-24,13);
        CHECK(DO(3,second,0,0)==0 && DO(41,2,1,0)==second,14);return 0;
    }
    if(mode=='d'){
        CHECK(DO(42,fd,address,16)==-13,15);
        CHECK(DO(41,1,1,0)==-97 && DO(41,2,2,0)==-93,16);
        CHECK(DO(49,fd,address,16)<0 && DO(50,fd,1,0)<0,17);return 0;
    }
    int enabled=1;
    CHECK(call(54,fd,6,1,(word)&enabled,4,0)==0,18);
    long connected=DO(42,fd,address,16);
    struct {int fd;short events,revents;} pollfd={(int)fd,4,0};
    if(mode=='n'){
        CHECK(connected==-115,19);
        CHECK(DO(7,&pollfd,1,5000)==1 && (pollfd.revents&4),20);
        int error=-1;unsigned size=4;
        CHECK(call(55,fd,1,4,(word)&error,(word)&size,0)==0 && error==0 && size==4,21);
    }else CHECK(connected==0,22);
    unsigned length=sizeof buffer;
    CHECK(DO(51,fd,buffer,&length)==0 && length==16 && buffer[0]==2,23);
    length=sizeof buffer;
    CHECK(DO(52,fd,buffer,&length)==0 && length==16 && buffer[4]==127,24);
    if(mode=='h' || mode=='o'){
        CHECK(DO(1,1,"network-ready\n",14)==14 && DO(0,0,buffer,1)==1 && buffer[0]=='G',40);
        CHECK(DO(3,fd,0,0)==0,41); return 0;
    }
    if(mode=='t'){
        word timeout[2]={0,50000};
        CHECK(call(54,fd,1,20,(word)timeout,16,0)==0,25);
        CHECK(DO(0,fd,buffer,1)==-11,26);return 0;
    }
    struct {const char *base;word length;} vectors[2]={{"pi",2},{"ng",2}};
    CHECK(DO(20,fd,vectors,2)==4,27);
    if(mode=='n'){
        CHECK(call(45,fd,(word)buffer,4,0x40,0,0)==-11,28);
        pollfd.events=1;word timeout[2]={5,0};
        CHECK(call(271,(word)&pollfd,1,(word)timeout,0,8,0)==1 && (pollfd.revents&1),29);
    }
    CHECK(DO(0,fd,buffer,0)==0 && DO(1,fd,buffer,0)==0,42);
    if(mode=='i'){
        struct {char *base;word length;} output[3]={{buffer,1},{buffer+1,0},{buffer+1,1}};
        long got=DO(19,fd,output,3); CHECK(got>0 && got<=2,43);
        while(got<4){long n=DO(0,fd,buffer+got,4-got);CHECK(n>0 && n<=4-got,44);got+=n;}
        CHECK(buffer[0]=='p' && buffer[1]=='i' && buffer[2]=='n' && buffer[3]=='g',45);
    }else CHECK(DO(0,fd,buffer,4)==4 && buffer[0]=='p' && buffer[3]=='g',30);
    if(mode=='b')return 0;
    if(mode=='q'){CHECK(DO(1,fd,"x",1)==-122,31);return 0;}
    long alias=DO(32,fd,0,0);CHECK(alias>=3 && DO(3,fd,0,0)==0,32);
    CHECK(DO(72,alias,4,2)==0,33);
    long child=DO(57,0,0,0);CHECK(child>=0,34);
    if(child==0)return DO(1,alias,"fork",4)==4?0:35;
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,36);
    CHECK(DO(0,alias,buffer,4)==4 && buffer[0]=='f' && buffer[3]=='k',37);
    CHECK(DO(48,alias,1,0)==0 && DO(0,alias,buffer,1)==0,38);
    CHECK(DO(3,alias,0,0)==0,39);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall network_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
