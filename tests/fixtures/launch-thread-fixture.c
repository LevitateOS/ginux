/* Actual shared fd tables, virtual TIDs, clear-TID joins and pinned pipe IO. */
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
static char stacks[32][16384] __attribute__((aligned(16)));
static volatile int tid[32], gate, count, error;
static volatile word thread_flags __attribute__((used))=0x3d0f00;
static int pair[2];
static char byte;
long spawn_thread(word top, volatile int *tid, long (*fn)(void));
__asm__(".global spawn_thread\nspawn_thread:\n"
        "mov %rdx,-16(%rdi)\nmov %rsi,%rdx\nmov %rsi,%r10\nmov %rdi,%rsi\nsub $16,%rsi\n"
        "xor %r8d,%r8d\nmov thread_flags(%rip),%edi\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 1f\n"
        "xor %ebp,%ebp\ncall *(%rsp)\nmov %rax,%rdi\nmov $60,%eax\nsyscall\nud2\n1:ret\n");
static void join(word i)
{
    for (;;) {
        int current=tid[i];
        if (!current) break;
        long result=DO(202,&tid[i],0,current);
        if (result!=0 && result!=-11 && result!=-4) { error=90; break; }
    }
}
static long quick(void) { return 0; }
static long basic(void)
{
    if (DO(39,0,0,0)!=1 || DO(186,0,0,0)!=tid[0] || tid[0]!=2 || DO(110,0,0,0)!=0) { error=11; return 0; }
    if (DO(3,3,0,0)!=0 || DO(2,"/dev/null",2,0)!=3) { error=12; return 0; }
    if (DO(0,4,&byte,1)!=1 || byte!='a') error=13;
    if (DO(83,"/work/directory",0700,0)!=0 || DO(80,"/work/directory",0,0)!=0) error=17;
    return 0;
}
static long pinned(void)
{
    if (DO(0,pair[0],&byte,1)!=1 || byte!='Q') error=21;
    return 0;
}
static long bounded(void)
{
    while (!gate) {
        long result=DO(202,&gate,0,0);
        if (result!=0 && result!=-11 && result!=-4) { error=31; return 0; }
    }
    if (DO(39,0,0,0)!=1 || DO(186,0,0,0)<2) error=32;
    __sync_fetch_and_add(&count,1);
    return 0;
}
static long forked(void)
{
    long child=DO(57,0,0,0);
    if (child==0) {
        long code=DO(110,0,0,0)==1 && DO(39,0,0,0)==3 ? 17 : 71;
        DO(60,code,0,0);
        __builtin_unreachable();
    }
    if (child!=3) error=72;
    else gate=(int)child;
    DO(202,&gate,1,1);
    return 0;
}
static long native_work(void)
{
    for (word i=0;i<32;++i) {
        char b;
        long fd=DO(2,"/input",0,0);
        if (fd<5 || DO(0,fd,&b,1)!=1 || b!='a' || DO(3,fd,0,0)!=0) { error=61; break; }
    }
    return 0;
}
static long after_leader(void)
{
    char input;
    if (DO(0,0,&input,1)!=1 || input!='G') return 41;
    char *args[]={"fixture","basic",0}, *env[]={0};
    if (DO(59,"/bin/fixture",args,env)!=-95) return 42;
    if (DO(39,0,0,0)!=1) return 43;
    DO(1,1,"owned-threads: PASS\n",20);
    return 0;
}
long thread_main(word *stack)
{
    word argc=*stack;
    char **argv=(char **)(stack+1);
    char mode=argc>1?argv[1][0]:'b';
    if (mode=='m') { thread_flags=0x7d0f00; mode='b'; }
    int pi=0;
    CHECK(DO(202,&pi,6,0)==-1 && pi==0,69);
    CHECK(DO(2,"/work/shared",0102,0600)==3 && DO(2,"/input",0,0)==4,10);
    if (mode=='t') {
        for (word attempt=0;attempt<256;++attempt) {
            long child=-11;
            for (word retry=0;retry<64 && child==-11;++retry) {
                child=spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],quick);
                if(child==-11) DO(39,0,0,0);
            }
            CHECK(child>1,83);
            join(0);
            CHECK(!error,84);
        }
    } else if (mode=='h') {
        CHECK(DO(22,pair,0,0)==0 && pair[0]==5,49);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],pinned)==2,50);
        CHECK(DO(1,1,"hold-ready\n",11)==11,51);
        for (;;) __asm__ volatile("pause");
    } else if (mode=='s') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],native_work)==2,62);
        for (word i=0;i<32;++i) {
            char b; long fd=DO(2,"/input",0,0);
            CHECK(fd>=5 && DO(0,fd,&b,1)==1 && b=='a' && DO(3,fd,0,0)==0,63);
            if (i==8) {
                long child=DO(57,0,0,0);
                if (child==0) { DO(60,0,0,0); __builtin_unreachable(); }
                int status;
                CHECK(child==3 && DO(61,child,&status,0)==child && status==0,64);
            }
        }
        join(0);
        CHECK(!error && DO(0,4,&byte,1)==1 && byte=='a',65);
    } else if (mode=='e') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],after_leader)==2,44);
        CHECK(DO(1,1,"leader-ready\n",13)==13,45);
        return 0; // Per-thread exit must keep the shared process alive.
    } else if (mode=='r') {
        word limit[2]={1,1}; CHECK(DO(302,0,6,limit)==0,46);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],basic)==-11 && tid[0]==0,47);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],basic)==-11 && tid[0]==0,48);
    } else if (mode=='b') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],basic)==2,14);
        join(0);
        CHECK(!error && tid[0]==0 && DO(0,3,&byte,1)==0,15);
        CHECK(DO(0,4,&byte,1)==1 && byte=='b',16);
        char cwd[32];
        CHECK(DO(79,cwd,sizeof cwd,0)==16,18);
        const char expected[]="/work/directory";
        for (word i=0;i<sizeof expected;++i) CHECK(cwd[i]==expected[i],19);
    } else if (mode=='p') {
        word action[4]={1,0,0,0};
        CHECK(call(13,13,(word)action,0,8,0,0)==0,20);
        CHECK(DO(22,pair,0,0)==0 && pair[0]==5 && pair[1]==6,22);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],pinned)==2,23);
        CHECK(DO(1,1,"pin-ready\n",10)==10 && DO(0,0,&byte,1)==1,24);
        CHECK(DO(3,5,0,0)==0 && DO(2,"/dev/null",2,0)==5,25);
        CHECK(DO(1,6,"Q",1)==1,26);
        join(0);
        CHECK(!error && DO(0,5,&byte,1)==0,27);
        CHECK(DO(1,6,"X",1)==-32,28); // Reader pin is released at return/exit.
    } else if (mode=='l') {
        for (word i=0;i<31;++i) CHECK(spawn_thread((word)(stacks[i]+sizeof stacks[i]),&tid[i],bounded)>1,33);
        CHECK(spawn_thread((word)(stacks[31]+sizeof stacks[31]),&tid[31],bounded)==-11 && tid[31]==0,34);
        gate=1;
        DO(202,&gate,1,31);
        for (word i=0;i<31;++i) join(i);
        CHECK(!error && count==31,35);
        long replacement=-11;
        for (word retry=0;retry<32 && replacement==-11;++retry) {
            replacement=spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],bounded);
            if (replacement==-11) DO(39,0,0,0);
        }
        CHECK(replacement>32,36);
        join(0);
        CHECK(!error && count==32,37);
    } else if (mode=='f') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],forked)==2,73);
        while (!gate && !error) DO(202,&gate,0,0);
        CHECK(!error && gate==3,74);
        int status;
        CHECK(DO(61,gate,&status,0)==gate && status==(17<<8),75);
        join(0);
        CHECK(!error,76);
    } else return 99;
    CHECK(DO(1,1,"owned-threads: PASS\n",20)==20,80);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall thread_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
