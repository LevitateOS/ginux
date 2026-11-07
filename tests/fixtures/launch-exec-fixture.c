/* Real configured exec replacement, failed exec, CLOEXEC and fork isolation. */
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
static char buffer[8];
static char *empty_env[]={0};
static int intact(void)
{
    if (DO(72,4,1,0)!=1 || DO(72,6,1,0)!=1 || DO(72,11,1,0)!=1 || DO(72,12,1,0)!=0 || DO(72,13,1,0)!=1) return 0;
    if (DO(8,4,0,0)!=0 || DO(0,4,buffer,1)!=1 || buffer[0]!='C') return 0;
    return DO(1,6,"discard",7)==7 && DO(8,11,0,1)==1;
}
static int path_is(const char *a, const char *b)
{ while (*a && *a==*b) { ++a; ++b; } return *a==*b; }
long exec_main(word *stack)
{
    word argc=*stack;
    char **argv=(char **)(stack+1), **env=argv+argc+1;
    char mode=argc>1 ? argv[1][0] : 's';
    char exe[64];
    long length=DO(89,"/proc/self/exe",exe,sizeof exe);
    if (mode=='/' && path_is(argv[1],"/allowed-elf")) { /* The allowed ELF's PT_INTERP runs this fixture. */
        const char expected[]="/allowed-elf";
        CHECK(length==sizeof expected-1,90);
        for(word i=0;i<sizeof expected-1;++i) CHECK(exe[i]==expected[i],94);
    } else CHECK(length>5 && exe[0]=='/' && exe[1]=='b' && exe[2]=='i' && exe[3]=='n' && exe[4]=='/',90);
    CHECK(call(267,-100,(word)"/proc/self/exe",(word)exe,4,0,0)==4,91);
    CHECK(DO(89,"/proc/self/exe",exe,0)==-22,92);
    CHECK(DO(89,"/proc/self/exe",1,8)==-14,93);
    if (mode=='X') return 99; // Hidden image script must never run.
    if (mode=='R') {
        int status=0;
        CHECK(DO(62,2,9,0)==0,95);
        CHECK(DO(61,2,&status,0)==2 && (status&127)==9,96);
        CHECK(DO(1,1,"shared-exec: PASS\n",18)==18,97);
        return 0;
    }
    if (mode=='S') {
        volatile char *shared=(volatile char *)call(9,0,4096,3,0x21,(word)-1,0);
        CHECK((long)shared>0,98);
        const char allowed[]="/bin/fixture", hidden[]="/work/hidden";
        for(word i=0;i<sizeof allowed;++i) shared[i]=allowed[i];
        volatile int *ready=(volatile int *)(shared+64);
        long child=DO(57,0,0,0);
        CHECK(child>=0,99);
        if(!child) {
            for(word iteration=0;;++iteration) {
                const char *path=iteration&1?allowed:hidden;
                for(word i=0;i<sizeof allowed-1;++i) shared[i]=path[i];
                if(iteration==1024) *ready=1;
            }
        }
        CHECK(child==2,100);
        while(!*ready) __asm__ volatile("pause");
        char *next[]={"fixture","R",0};
        for(word i=0;i<1024;++i) {
            long result=DO(59,shared,next,empty_env);
            CHECK(result<0,101);
        }
        return 102;
    }
    if (mode=='/') return 77; // Interpreter of the allowed image script.
    if (mode=='u') {
        char *args[]={"probe",0};
        for(word i=0;i<4;++i) {
            const char *paths[]={"/image-script","/image-elf","/link-script","/mixed-script"};
            CHECK(DO(59,paths[i],args,empty_env)==-95,73);
        }
        CHECK(call(322,-100,(word)"/image-elf",(word)args,(word)empty_env,0x100,0)==-95,74);
        for(word i=0;i<2;++i) {
            long fd=DO(2,i?"/image-elf":"/image-script",0,0);
            CHECK(fd>=3,75);
            CHECK(call(322,fd,(word)"",(word)args,(word)empty_env,0x1000,0)==-95,76);
            CHECK(DO(3,fd,0,0)==0,77);
        }
        for(word image=0;image<2;++image) {
            char *allowed_args[]={"probe","/allowed-elf",0};
            long child=DO(57,0,0,0);
            if(child==0) { DO(59,image?"/allowed-elf":"/allowed-script",allowed_args,empty_env); return 78; }
            int status=-1;
            CHECK(child==(long)(2+image) && DO(61,child,&status,0)==child && status==(77<<8),79);
        }
        CHECK(DO(1,1,"interpreter-guards: PASS\n",25)==25,80);
        return 0;
    }
    if (mode=='a') {
        CHECK(DO(39,0,0,0)==(argv[2][0]=='c'?2:1),10);
        CHECK(env[0] && env[0][0]=='E' && env[0][5]=='y' && !env[1],11);
        CHECK(DO(0,4,buffer,1)==-9 && DO(0,6,buffer,1)==-9,12);
        CHECK(DO(0,7,buffer,1)==-9 && DO(1,8,"X",1)==-9 && DO(0,11,buffer,1)==-9,13);
        CHECK(DO(0,13,buffer,1)==-9 && DO(0,14,buffer,1)==-9,14);
        // Runner inspects native kernel descriptors before any new open can hide a leak.
        CHECK(DO(1,1,"after-ready\n",12)==12 && DO(0,0,buffer,1)==1 && buffer[0]=='G',15);
        CHECK(DO(0,3,buffer,1)==1 && buffer[0]=='K',16);
        CHECK(DO(0,5,buffer,1)==0,17);
        CHECK(DO(0,9,buffer,1)==1 && buffer[0]=='Q',18);
        CHECK(DO(3,10,0,0)==0 && DO(0,9,buffer,1)==0,19);
        CHECK(DO(0,12,buffer,1)==1 && buffer[0]=='b',20);
        CHECK(DO(72,12,1,0)==0 && DO(72,12,2,1)==0,21);
        CHECK(DO(2,"/input",02000000,0)==4,22); // Reuses the freed public and raw slots.
        char *next[]={"second","final",0};
        DO(59,"/bin/second",next,empty_env);
        return 23;
    }
    if (mode=='f') {
        CHECK(DO(0,4,buffer,1)==-9 && DO(0,12,buffer,1)==-9,24);
        CHECK(DO(8,3,0,0)==0 && DO(0,3,buffer,1)==1 && buffer[0]=='K',25);
        CHECK(DO(0,5,buffer,1)==0 && DO(0,9,buffer,1)==0,26);
        CHECK(DO(1,1,"exec: PASS\n",11)==11,27);
        return 0;
    }
    CHECK(DO(2,"/work/keep",0102,0600)==3 && DO(1,3,"K",1)==1 && DO(8,3,0,0)==0,30);
    CHECK(DO(2,"/work/closed",02000102,0600)==4 && DO(1,4,"C",1)==1,31);
    CHECK(DO(2,"/dev/null",2,0)==5 && DO(2,"/dev/null",02000002,0)==6,32);
    int pair[2];
    CHECK(DO(293,pair,02000000,0)==0 && pair[0]==7 && pair[1]==8,33);
    CHECK(DO(32,7,0,0)==9 && DO(32,8,0,0)==10 && DO(1,8,"Q",1)==1,34);
    CHECK(DO(2,"/input",02000000,0)==11 && DO(32,11,0,0)==12 && DO(2,"/input",02000000,0)==13,35);
    CHECK(DO(0,11,buffer,1)==1 && buffer[0]=='a',36);
    char *next[]={"second","after",mode=='c'?"child":"root",0};
    char *next_env[]={"EXEC=yes",0};
    if (mode=='b') {
        CHECK(DO(59,"/missing",next,next_env)==-2 && intact(),40);
        CHECK(DO(59,"/noexec",next,next_env)==-13 && intact(),41);
        CHECK(DO(59,"/bin",next,next_env)==-13 && intact(),81);
        CHECK(DO(59,"/malformed",next,next_env)==-8 && intact(),42);
        CHECK(DO(59,"/bin/second",1,next_env)==-14 && intact(),43);
        CHECK(DO(59,1,next,next_env)==-14 && intact(),44);
        CHECK(DO(59,"/work/closed",next,next_env)==-13 && intact(),45);
        CHECK(DO(59,"/work/hidden",next,next_env)==-2 && intact(),46);
        CHECK(DO(59,"/owned-link",next,next_env)==-2 && intact(),70);
        CHECK(call(322,-100,(word)"/bin/link",(word)next,(word)next_env,0x100,0)==-40 && intact(),71);
        long failed=59;
        word path=(word)"/work/../bin/second", arguments=1, environment=(word)next_env;
        __asm__ volatile("syscall":"+a"(failed),"+D"(path),"+S"(arguments),"+d"(environment)::"rcx","r11","memory");
        CHECK(failed==-14 && path==(word)"/work/../bin/second" && arguments==1 && environment==(word)next_env && intact(),72);
        CHECK(DO(59,"/dev/null",next,next_env)==-13 && intact(),47);
        CHECK(call(322,4,(word)"",(word)next,(word)next_env,0x1000,0)==-13 && intact(),48);
    }
    if (mode=='c') {
        long child=DO(57,0,0,0);
        if (child) {
            CHECK(child==2,50);
            for (word i=7;i<=10;++i) CHECK(DO(3,i,0,0)==0,51);
            int status;
            CHECK(DO(61,child,&status,0)==child && status==0,52);
            CHECK(DO(72,4,1,0)==1 && DO(8,4,0,0)==0 && DO(0,4,buffer,1)==1 && buffer[0]=='C',53);
            CHECK(DO(1,6,"parent",6)==6 && DO(72,13,1,0)==1,54);
            CHECK(DO(1,1,"parent: PASS\n",13)==13,55);
            return 0;
        }
    }
    if (mode=='d') {
        CHECK(DO(2,"/bin/second",02000000,0)==14,60);
        call(322,14,(word)"",(word)next,(word)next_env,0x1000,0);
    } else if (mode=='p') {
        call(322,-1,(word)"/bin/second",(word)next,(word)next_env,0,0);
    } else {
        DO(59,mode=='r'?"../bin/second":mode=='l'?"/bin/link":"/bin/second",next,next_env);
    }
    return 61;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall exec_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
