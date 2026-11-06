/* Kernel shebang argv, named paths, rollback and private descriptor lifetime. */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e)
{
    register word r10 __asm__("r10")=d, r8 __asm__("r8")=e;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c),
                     "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0)
#define CHECK(expr,code) do { if (!(expr)) return code; } while (0)
static char buffer[4096];
static char *many[4098];
static word length(const char *s) { word n=0; while(s[n]) ++n; return n; }
static int equal(const char *a, const char *b) {
    while (*a && *a==*b) { ++a; ++b; } return *a==*b;
}
static long publish(const char *path, const char *data) {
    long fd=DO(2,path,0102,0600); if (fd<0) return fd;
    if (DO(1,fd,data,length(data))!=(long)length(data) || DO(91,fd,0755,0) || DO(3,fd,0,0)) return -1;
    return 0;
}
static int intact(void) { return DO(72,3,1,0)==1 && DO(72,4,1,0)==0 && DO(72,5,1,0)==1; }
static int ordinary_mode(const char *s) {
    const char *prefix="ordinary-";
    while(*prefix && *prefix==*s) { ++prefix; ++s; }
    return !*prefix;
}
static int copy_program(void) {
    long input=DO(2,"/bin/interpreter",0,0), output=DO(2,"/work/interpreter",0102,0600);
    if(input<0 || output<0) return -1;
    long n;
    while((n=DO(0,input,buffer,sizeof buffer))>0) {
        if(DO(1,output,buffer,n)!=n) return -1;
    }
    if(n<0 || DO(91,output,0755,0) || DO(3,output,0,0) || DO(3,input,0,0)) return -1;
    return 0;
}
static long ordinary(word argc, char **argv, char **env) {
    const char *mode=argv[argc-1];
    int descriptor=equal(mode,"ordinary-fd") || equal(mode,"ordinary-unlinked");
    int directory=equal(mode,"ordinary-dir") || equal(mode,"ordinary-renamed");
    int cross=equal(mode,"ordinary-cross") || equal(mode,"ordinary-cross-nested") || equal(mode,"ordinary-cross-relative") || equal(mode,"ordinary-cross-cwd") || equal(mode,"ordinary-cross-plain");
    int chain=equal(mode,"ordinary-chain");
    int owned=chain || equal(mode,"ordinary-owned") || equal(mode,"ordinary-interpreter-link");
    int nested=equal(mode,"ordinary-nested") || equal(mode,"ordinary-joined") || equal(mode,"ordinary-cross-nested");
    int plain=equal(mode,"ordinary-plain") || equal(mode,"ordinary-cross-plain");
    if(!equal(argv[0],"/bin/fixture")) {
        CHECK(equal(argv[0],owned?(equal(mode,"ordinary-interpreter-link")?"/work/interpreter-link":"/work/interpreter"):(cross && !nested?(equal(mode,"ordinary-cross-cwd")?"interpreter-link":(equal(mode,"ordinary-cross-relative")?"work/interpreter-link":"/work/interpreter-link")):"/bin/interpreter")),70);
        CHECK(env[0] && equal(env[0],"SCRIPT_ENV=present") && env[1] && equal(env[1],"SECOND=two words") && !env[2],71);
        CHECK(argc==(word)(chain?10:(nested?6:(plain?3:4))),72);
        const char *name=argv[argc-2];
        CHECK(equal(name,descriptor?"/dev/fd/6":(directory?"/dev/fd/6/program":(equal(mode,"ordinary-relative")?"work/program":(equal(mode,"ordinary-script-link")?"/work/alias":"/work/program")))),73);
        if(chain) {
            CHECK(equal(argv[1],"fourth option") && equal(argv[2],"/work/fourth") &&
                  equal(argv[3],"third option") && equal(argv[4],"/work/third") &&
                  equal(argv[5],"second option") && equal(argv[6],"/work/second") && equal(argv[7],"option with spaces"),74);
        } else {
            if(!plain) CHECK(equal(argv[nested?3:1],"option with spaces"),75);
            if(nested) CHECK(equal(argv[1],"nested option") && equal(argv[2],equal(mode,"ordinary-joined")?"/work/middle":(equal(mode,"ordinary-cross-nested")?"/work/interpreter-link":"/bin/wrapper")),76);
        }
        CHECK(DO(72,3,1,0)==-9 && DO(72,5,1,0)==-9 && DO(72,4,1,0)==0,77);
        CHECK(DO(8,4,0,0)==0 && DO(0,4,buffer,1)==1 && buffer[0]=='K',78);
        long fd=DO(2,name,0,0); CHECK(fd>=3 && DO(0,fd,buffer,2)==2 && buffer[0]=='#' && buffer[1]=='!',79);
        if(cross) {
            CHECK(DO(0,fd,buffer,5)==5,100);
            CHECK(buffer[0]==(equal(mode,"ordinary-cross-cwd")?'i':(equal(mode,"ordinary-cross-relative")?'w':'/')),101);
        }
        CHECK(DO(3,fd,0,0)==0,79);
        if(descriptor) CHECK(DO(8,6,0,1)==7,80);
        // Script bytes become writable data after the interpreter commits.
        if(!descriptor && !directory) {
            fd=DO(2,name,1,0); CHECK(fd>=3 && DO(3,fd,0,0)==0,81);
        }
        CHECK(DO(1,1,"script: PASS\n",13)==13,82); return 0;
    }
    CHECK(argc==2,83);
    if(owned) CHECK(copy_program()==0,84);
    CHECK(publish("/work/program",plain?"#!/bin/interpreter\nbody\n":
          (nested?(equal(mode,"ordinary-joined")?"#!/work/middle option with spaces\nbody\n":"#!/bin/wrapper option with spaces\nbody\n"):
          (chain?"#!/work/second option with spaces\nbody\n":
          (owned?(equal(mode,"ordinary-interpreter-link")?"#!/work/interpreter-link option with spaces\nbody\n":"#!/work/interpreter option with spaces\nbody\n"):"#! \t/bin/interpreter\toption with spaces \t\nbody\n"))))==0,85);
    if(cross) {
        CHECK(DO(88,equal(mode,"ordinary-cross-nested")?"/bin/wrapper":"/bin/interpreter","/work/interpreter-link",0)==0,98);
        CHECK(publish("/work/program",equal(mode,"ordinary-cross-cwd")?"#!interpreter-link option with spaces\nbody\n":(equal(mode,"ordinary-cross-plain")?"#!/work/interpreter-link\nbody\n":(equal(mode,"ordinary-cross-relative")?"#!work/interpreter-link option with spaces\nbody\n":"#!/work/interpreter-link option with spaces\nbody\n")))==0,99);
    }
    if(equal(mode,"ordinary-joined")) CHECK(publish("/work/middle","#!/bin/interpreter nested option\n")==0,95);
    if(equal(mode,"ordinary-script-link")) CHECK(DO(88,"program","/work/alias",0)==0,96);
    if(equal(mode,"ordinary-interpreter-link")) CHECK(DO(88,"interpreter","/work/interpreter-link",0)==0,97);
    if(chain) CHECK(publish("/work/second","#!/work/third second option\n")==0 &&
                    publish("/work/third","#!/work/fourth third option\n")==0 &&
                    publish("/work/fourth","#!/work/interpreter fourth option\n")==0,86);
    CHECK(DO(2,"/work/drop",02000102,0600)==3 && DO(2,"/work/keep",0102,0600)==4 && DO(1,4,"K",1)==1 && DO(2,"/input",02000000,0)==5,87);
    if(descriptor) {
        CHECK(DO(2,"/work/program",0,0)==6 && DO(8,6,7,0)==7,88);
        if(equal(mode,"ordinary-unlinked")) CHECK(DO(87,"/work/program",0,0)==0,89);
    }
    if(directory) {
        CHECK(DO(2,"/work",0200000,0)==6,90);
        if(equal(mode,"ordinary-renamed")) {
            CHECK(DO(83,"/work/sub",0755,0)==0 && DO(82,"/work/program","/work/sub/program",0)==0 &&
                  DO(3,6,0,0)==0 && DO(2,"/work/sub",0200000,0)==6 && DO(82,"/work/sub","/work/moved",0)==0,91);
        }
    }
    if(equal(mode,"ordinary-fork") || equal(mode,"ordinary-vfork")) {
        long child=DO(equal(mode,"ordinary-vfork")?58:57,0,0,0); CHECK(child>=0,92);
        if(child) { int status=-1; CHECK(DO(61,child,&status,0)==child && status==0 && intact(),93);
            DO(1,1,"parent: PASS\n",13); return 0; }
    }
    if(equal(mode,"ordinary-cross-cwd")) CHECK(DO(80,"/work",0,0)==0,102);
    char *next[]={"ignored-argv-zero",(char *)mode,0};
    char *next_env[]={"SCRIPT_ENV=present","SECOND=two words",0};
    if(descriptor) call(322,6,(word)"",(word)next,(word)next_env,0x1000);
    else if(directory) call(322,6,(word)"program",(word)next,(word)next_env,0);
    else if(equal(mode,"ordinary-at")) call(322,-999,(word)"/work/program",(word)next,(word)next_env,0);
    else DO(59,equal(mode,"ordinary-relative")?"work/program":(equal(mode,"ordinary-script-link")?"/work/alias":"/work/program"),next,next_env);
    return 94;
}
long script_main(word *stack)
{
    word argc=*stack;
    char **argv=(char **)(stack+1), **env=argv+argc+1;
    if(argc && ordinary_mode(argv[argc-1])) return ordinary(argc,argv,env);
    if (equal(argv[0],"/bin/interpreter")) {
        CHECK(env[0] && equal(env[0],"SCRIPT_ENV=present") && env[1] && equal(env[1],"SECOND=two words") && !env[2],10);
        const char *mode=argv[argc-1];
        int large=equal(mode,"many");
        const char *name=argv[large?2:argc-2];
        int plain=equal(mode,"plain");
        int nested=equal(mode,"nested");
        int descriptor=equal(mode,"descriptor") || equal(mode,"unlinked") || equal(mode,"fd-fork") || equal(mode,"fd-vfork");
        int directory=equal(mode,"dir-relative") || equal(mode,"dir-renamed");
        CHECK(argc==(word)(large?4098:(plain?3:(nested?6:4))),11);
        if(large) for(word n=3;n<argc-1;++n) CHECK(equal(argv[n],"padding"),23);
        if (!plain) CHECK(equal(argv[nested?3:1],"option with spaces"),12);
        if (nested) CHECK(equal(argv[1],"nested option") && equal(argv[2],"/bin/wrapper"),13);
        CHECK(equal(name,descriptor?"/dev/fd/6":(directory?"/dev/fd/6/program":(equal(mode,"relative")?"work/program":"/work/program"))),14);
        word *aux=(word *)(env+3); int found=0;
        while(aux[0]) { if(aux[0]==31) { CHECK(equal((char *)aux[1],name),15); found=1; } aux+=2; }
        CHECK(found,16);
        CHECK(DO(72,3,1,0)==-9 && DO(72,5,1,0)==-9,17);
        CHECK(DO(8,4,0,0)==0 && DO(0,4,buffer,1)==1 && buffer[0]=='K',18);
        long fd=DO(2,name,0,0); CHECK(fd>=3,19);
        CHECK(DO(0,fd,buffer,sizeof buffer)>2 && buffer[0]=='#' && buffer[1]=='!' && DO(3,fd,0,0)==0,20);
        // A script is readable data once its interpreter starts, not a running ELF pin.
        fd=DO(2,name,1,0);
        if(descriptor || directory) CHECK(fd==-13,21);
        else CHECK(fd>=3 && DO(3,fd,0,0)==0,21);
        if(descriptor) CHECK(DO(8,6,0,1)==7,24);
        CHECK(DO(1,1,"script-ready\n",13)==13 && DO(0,0,buffer,1)==1 && buffer[0]=='G',22);
        DO(1,1,"script: PASS\n",13); return 0;
    }
    CHECK(argc==2,30);
    const char *mode=argv[1];
    CHECK(publish("/work/program",equal(mode,"plain")?"#!/bin/interpreter\nbody\n":
        (equal(mode,"nested")?"#!/bin/wrapper option with spaces\nbody\n":"#! \t/bin/interpreter\toption with spaces \t\nbody\n"))==0,31);
    CHECK(DO(2,"/work/drop",02000102,0600)==3 && DO(2,"/work/keep",0102,0600)==4 && DO(1,4,"K",1)==1,32);
    CHECK(DO(2,"/input",02000000,0)==5,33);
    char *next[]={"ignored-argv-zero",(char *)mode,0};
    char *next_env[]={"SCRIPT_ENV=present","SECOND=two words",0};
    CHECK(DO(90,"/work/program",0644,0)==0 && DO(59,"/work/program",next,next_env)==-13 && intact(),34);
    CHECK(DO(90,"/work/program",0755,0)==0,35);
    for(word n=0;n<4097;++n) many[n]="padding";
    CHECK(DO(59,"/work/program",many,next_env)==-7 && intact(),48);
    CHECK(DO(59,"/work/program",next,many)==-7 && intact(),49);
    CHECK(DO(59,"/work/program",next,1)==-14 && intact(),50);
    long fd=DO(2,"/work/program",1,0); CHECK(fd==6 && DO(59,"/work/program",next,next_env)==-26 && DO(3,fd,0,0)==0,36);
    for(int n=0;n<3;++n) {
        CHECK(DO(59,"/work/program",1,next_env)==-14 && intact(),37);
        fd=DO(2,"/work/program",1,0); CHECK(fd==6 && DO(3,fd,0,0)==0,38);
        CHECK(publish("/work/missing","#!/bin/missing\n")==0 && DO(59,"/work/missing",next,next_env)==-2 && intact(),39);
    }
    CHECK(publish("/work/invalid","#! \t\n")==0 && DO(59,"/work/invalid",next,next_env)==-8 && intact(),40);
    CHECK(publish("/work/owned-interpreter","#!/work/owned-interpreter\n")==0 && DO(59,"/work/owned-interpreter",next,next_env)==-40 && intact(),41);
    fd=DO(2,"/work/program",02000000,0);
    CHECK(fd==6 && call(322,fd,(word)"",(word)next,(word)next_env,0x1000)==-2 && intact(),42);
    CHECK(DO(72,fd,2,0)==0 && DO(8,fd,7,0)==7,43);
    long reopened=DO(257,-999,"/dev/fd/6",02000000);
    CHECK(reopened==7 && DO(72,reopened,1,0)==1 && DO(0,reopened,buffer,2)==2 && buffer[0]=='#' && buffer[1]=='!',52);
    CHECK(DO(2,"/dev/fd/4294967302",0,0)==-2,61);
    CHECK(DO(8,fd,0,1)==7 && DO(2,"/dev/fd/6",1,0)==-13 && DO(3,reopened,0,0)==0 && DO(3,fd,0,0)==0,53);
    CHECK(DO(2,"/dev/fd/6",0,0)==-2 && DO(2,"/dev/fd/5",0,0)==-95 && DO(2,"/dev/fd/nope",0,0)==-2,54);
    fd=DO(2,"/work",02200000,0);
    CHECK(fd==6 && call(322,fd,(word)"program",(word)next,(word)next_env,0)==-2 && DO(3,fd,0,0)==0,51);
    CHECK(DO(1,1,"failed-ready\n",13)==13 && DO(0,0,buffer,1)==1 && buffer[0]=='G',44);
    int descriptor=equal(mode,"descriptor") || equal(mode,"unlinked") || equal(mode,"fd-fork") || equal(mode,"fd-vfork");
    int directory=equal(mode,"dir-relative") || equal(mode,"dir-renamed");
    if(descriptor) {
        CHECK(DO(2,"/work/program",0,0)==6 && DO(8,6,7,0)==7,55);
        if(equal(mode,"unlinked")) CHECK(DO(87,"/work/program",0,0)==0,56);
    }
    if(directory) {
        CHECK(DO(2,"/work",0200000,0)==6,57);
        CHECK(DO(2,"/dev/fd/6/../../input",0,0)==-95,58);
        if(equal(mode,"dir-renamed")) {
            CHECK(DO(83,"/work/sub",0755,0)==0 && DO(82,"/work/program","/work/sub/program",0)==0,59);
            CHECK(DO(3,6,0,0)==0 && DO(2,"/work/sub",0200000,0)==6 && DO(82,"/work/sub","/work/moved",0)==0,60);
        }
    }
    if(equal(mode,"fork") || equal(mode,"vfork") || equal(mode,"clone") || equal(mode,"fd-fork") || equal(mode,"fd-vfork")) {
        long child=equal(mode,"clone")?DO(56,0x4111,0,0):DO((equal(mode,"vfork") || equal(mode,"fd-vfork"))?58:57,0,0,0);
        CHECK(child>=0,45);
        if(child) {
            int status=-1; CHECK(DO(61,child,&status,0)==child && status==0 && intact(),46);
            DO(1,1,"parent: PASS\n",13); return 0;
        }
    }
    if(descriptor) call(322,6,(word)"",(word)next,(word)next_env,0x1000);
    else if(directory) call(322,6,(word)"program",(word)next,(word)next_env,0);
    else if(equal(mode,"many")) { many[4095]=(char *)mode; many[4096]=0; DO(59,"/work/program",many,next_env); }
    else if(equal(mode,"at")) call(322,-999,(word)"/work/program",(word)next,(word)next_env,0);
    else DO(59,equal(mode,"relative")?"work/program":"/work/program",next,next_env);
    return 47;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall script_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
