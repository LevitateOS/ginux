/* Generated ELF replacement, private-fd cleanup and VFS executable lifetime. */
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
static char buffer[4096];
static char *empty_env[]={0};
static int intact(void)
{
    return DO(72,3,1,0)==1 && DO(72,5,1,0)==1 && DO(72,6,1,0)==1 && DO(72,7,1,0)==0
        && DO(8,5,0,0)==0 && DO(0,5,buffer,1)==1 && buffer[0]=='C';
}
static long publish(const char *path, const char *data, word size)
{
    long fd=DO(2,path,0102,0600); if (fd<0) return fd;
    if (DO(1,fd,data,size)!=(long)size || DO(91,fd,0755,0)!=0 || DO(3,fd,0,0)!=0) return -1;
    return 0;
}
long owned_exec_main(word *stack)
{
    word argc=*stack;
    char **argv=(char **)(stack+1), **env=argv+argc+1;
    char mode=argc>1 ? argv[1][0] : 's';
    if (mode=='r' && argc>2 && argv[1][1]=='e') {
        CHECK(DO(2,"/work/program",1,0)==-26,10); // Forked child still owns the executable.
        CHECK(DO(1,9,"Z",1)==1 && DO(3,9,0,0)==0,11);
        int status=-1; CHECK(DO(61,-1,&status,0)>0 && status==0,12);
        long fd=DO(2,"/work/program",1,0); CHECK(fd>=3 && DO(3,fd,0,0)==0,13);
        DO(1,1,"owned-exec: PASS\n",17); return 0;
    }
    if (mode=='a') {
        const char *expected=argv[2][0]=='u'?"/work/program (deleted)":"/work/program";
        long length=DO(89,"/proc/self/exe",buffer,sizeof buffer);
        long wanted=argv[2][0]=='u'?23:13;
        CHECK(length==wanted,90);
        for (long i=0;i<length;i++) CHECK(buffer[i]==expected[i],91);
        CHECK(argc==3 && env[0] && env[0][0]=='O' && env[0][6]=='y' && !env[1],14);
        CHECK(DO(72,3,1,0)==-9 && DO(72,5,1,0)==-9 && DO(72,6,1,0)==-9 && DO(72,8,1,0)==-9,15);
        CHECK(DO(8,4,0,0)==0 && DO(0,4,buffer,1)==1 && buffer[0]=='K',16);
        CHECK(DO(0,7,buffer,1)==1 && buffer[0]=='Q',17);
        CHECK(DO(1,1,"owned-ready\n",12)==12 && DO(0,0,buffer,1)==1 && buffer[0]=='G',18);
        if (argv[2][0]=='u') {
            CHECK(publish("/work/program","new",3)==0,19); // Deleted running object is distinct from new name.
            DO(1,1,"owned-exec: PASS\n",17); return 0;
        }
        CHECK(DO(2,"/work/program",1,0)==-26,20);
        int pair[2]; CHECK(DO(22,pair,0,0)==0 && pair[0]==3 && pair[1]==5,21);
        CHECK(DO(33,pair[0],8,0)==8 && DO(33,pair[1],9,0)==9,22);
        CHECK(DO(3,pair[0],0,0)==0 && DO(3,pair[1],0,0)==0,23);
        long child=DO(57,0,0,0); CHECK(child>=0,24);
        if (!child) {
            CHECK(DO(3,9,0,0)==0 && DO(0,8,buffer,1)==1 && buffer[0]=='Z',25);
            return 0;
        }
        CHECK(DO(3,8,0,0)==0,26);
        char *next[]={"payload","released",argv[2],0};
        DO(59,"/bin/payload",next,empty_env); return 27;
    }
    long source=DO(2,"/bin/payload",0,0), dest=DO(2,"/work/program",0102,0600);
    CHECK(source>=3 && dest>=3,30);
    for (;;) {
        long count=DO(0,source,buffer,sizeof buffer); CHECK(count>=0,31);
        if (!count) break;
        CHECK(DO(1,dest,buffer,count)==count,32);
    }
    CHECK(DO(91,dest,0755,0)==0 && DO(3,source,0,0)==0 && DO(3,dest,0,0)==0,33);
    CHECK(DO(2,"/work/program",02000000,0)==3,34);
    CHECK(DO(2,"/work/keep",0102,0600)==4 && DO(1,4,"K",1)==1,35);
    CHECK(DO(2,"/work/drop",02000102,0600)==5 && DO(1,5,"C",1)==1,36);
    CHECK(DO(2,"/input",02000000,0)==6 && DO(32,6,0,0)==7,37);
    char *next[]={"payload","after",argv[1],0}, *next_env[]={"OWNED=yes",0};
    CHECK(DO(59,"/work/missing",next,next_env)==-2 && intact(),38);
    CHECK(DO(90,"/work/program",0644,0)==0 && DO(59,"/work/program",next,next_env)==-13 && intact(),39);
    CHECK(DO(90,"/work/program",0755,0)==0,40);
    long writer=DO(2,"/work/program",2,0);
    CHECK(writer==8 && DO(59,"/work/program",next,next_env)==-26 && DO(3,writer,0,0)==0 && intact(),41);
    for (int i=0;i<3;++i) {
        CHECK(DO(59,"/work/program",1,next_env)==-14 && intact(),42);
        writer=DO(2,"/work/program",1,0); CHECK(writer==8 && DO(3,writer,0,0)==0,43); // Failed exec released its pin.
    }
    CHECK(DO(8,3,0,0)==0 && DO(0,3,buffer,64)==64,44);
    CHECK(publish("/work/bad-elf",buffer,64)==0 && DO(59,"/work/bad-elf",next,next_env)==-8 && intact(),45);
    CHECK(publish("/work/script","#!/bin/missing\n",15)==0 && DO(59,"/work/script",next,next_env)==-2 && intact(),46);
    CHECK(DO(1,1,"failed-ready\n",13)==13 && DO(0,0,buffer,1)==1 && buffer[0]=='G',47);
    if (mode=='c' || mode=='v' || mode=='m') {
        long child=mode=='m' ? DO(56,0x4111,0,0) : DO(mode=='v'?58:57,0,0,0);
        CHECK(child>=0,48);
        if (child) {
            int status=-1; CHECK(DO(61,child,&status,0)==child && status==0 && intact() && DO(8,3,0,1)==64,49);
            writer=DO(2,"/work/program",1,0); CHECK(writer>=3 && DO(3,writer,0,0)==0,50);
            DO(1,1,"owned-parent: PASS\n",19); return 0;
        }
    }
    if (mode=='d' || mode=='u') {
        if (mode=='u') CHECK(DO(87,"/work/program",0,0)==0,51);
        call(322,3,(word)"",(word)next,(word)next_env,0x1000,0);
    } else if (mode=='r') {
        CHECK(DO(2,"/work",02200000,0)==8,52);
        call(322,8,(word)"program",(word)next,(word)next_env,0,0);
    } else DO(59,"/work/program",next,next_env);
    return 53;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall owned_exec_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
