/* Signals against supervisor-held syscalls, task creation racing death, and
   thread-directed signals (tkill, tgkill) as raise, abort and pthread_kill use them. */
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
struct clock_time { long seconds, nanos; };
struct poll_fd { int fd; short events, revents; };
static volatile int handled, handled_signal;
static int wake_pipe[2];
void signal_return(void);
__asm__(".global signal_return\nsignal_return:\nmov $15,%eax\nsyscall\nud2\n");
static void handler(int signal) { ++handled; handled_signal=signal; DO(1,wake_pipe[1],"x",1); }
static long install(int signal, word flags)
{
    word action[4]={(word)handler,0x04000000UL|flags,(word)signal_return,0};
    return call(13,signal,(word)action,0,8,0,0);
}
static void say(const char *text) { long n=0; while (text[n]) ++n; DO(1,1,text,n); }
static void spin(long n) { for (volatile long i=0;i<n;++i); }
static long fork_(void) { return call(56,17,0,0,0,0,0); }
static long now_ms(void)
{
    struct clock_time t;
    if (DO(228,1,&t,0)!=0) return -1;
    return t.seconds*1000+t.nanos/1000000;
}
/* The runner releases this child only after it has seen the parent park. */
static long released_child(void)
{
    long pid=fork_();
    if (pid==0) { char byte; DO(60,DO(0,0,&byte,1)==1?0:9,0,0); }
    return pid;
}
static char stacks[16][16384] __attribute__((aligned(16)));
static volatile int tid[16];
static volatile word thread_flags __attribute__((used))=0x3d0f00;
long spawn_thread(word top, volatile int *tid, long (*fn)(void));
__asm__(".global spawn_thread\nspawn_thread:\n"
        "mov %rdx,-16(%rdi)\nmov %rsi,%rdx\nmov %rsi,%r10\nmov %rdi,%rsi\nsub $16,%rsi\n"
        "xor %r8d,%r8d\nmov thread_flags(%rip),%edi\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 1f\n"
        "xor %ebp,%ebp\ncall *(%rsp)\nmov %rax,%rdi\nmov $60,%eax\nsyscall\nud2\n1:ret\n");
static long quick(void) { return 0; }
static long spawner(void)
{
    for (word k=1;;k=k%14+1) {
        while (tid[k]) __asm__ volatile("pause");
        spawn_thread((word)(stacks[k]+sizeof stacks[k]), &tid[k], quick);
    }
    return 0;
}
static volatile int handler_tid, sibling_result, sibling_go;
static int sibling_pipe[2];
static void tid_handler(int signal) { handled_signal=signal; handler_tid=(int)DO(186,0,0,0); ++handled; }
static long install_tid(int signal)
{
    word action[4]={(word)tid_handler,0x04000000UL,(word)signal_return,0};
    return call(13,signal,(word)action,0,8,0,0);
}
static long spinning_sibling(void) { while (!handled) __asm__ volatile("pause"); return 0; }
static long parked_sibling(void)
{
    char byte;
    sibling_go=1;
    sibling_result=(int)DO(0,sibling_pipe[0],&byte,1);
    return 0;
}
/* glibc raise(): block every signal, signal this thread, restore the mask. */
static long glibc_raise(int signal)
{
    word all=~0UL, saved=0;
    if (call(14,0,(word)&all,(word)&saved,8,0,0)!=0) return -1000;
    long result=DO(234,DO(39,0,0,0),DO(186,0,0,0),signal);
    if (call(14,2,(word)&saved,0,8,0,0)!=0) return -1001;
    return result;
}
static long decimal(const char *text)
{
    long value=0;
    while (*text>='0' && *text<='9') value=value*10+(*text++-'0');
    return value;
}
static int same(const char *a, const char *b)
{
    while (*a && *a==*b) { ++a; ++b; }
    return *a==*b;
}
long signal_main(word *stack)
{
    char **argv=(char **)(stack+1);
    const char *mode=stack[0]>1?argv[1]:"";
    char byte=0;
    long status=0;
    if (same(mode,"exec-done")) { say("held-signals: PASS\n"); return 0; }
    if (same(mode,"abort-init")) { glibc_raise(6); return 120; }
    CHECK(DO(293,wake_pipe,0,0)==0,10);

    /* A handler ends a parked wait; the kernel applies its restart flags. */
    if (same(mode,"park-read") || same(mode,"park-read-restart")) {
        int restart=same(mode,"park-read-restart");
        CHECK(install(17,restart?0x10000000UL:0)==0,20);
        long child=released_child();
        CHECK(child>0,21);
        long result=DO(0,wake_pipe[0],&byte,1);
        CHECK(handled==1 && handled_signal==17,22);
        if (restart) { CHECK(result==1 && byte=='x',23); }
        else { CHECK(result==-4 && DO(0,wake_pipe[0],&byte,1)==1 && byte=='x',24); }
        CHECK(call(61,child,(word)&status,0,0,0,0)==child && status==0,25);
    } else if (same(mode,"pending-pselect") || same(mode,"pending-zero-pselect") || same(mode,"ready-pselect")) {
        word original=1UL<<(17-1), temporary=0, current=0, read[4]={1UL<<wake_pipe[0]};
        word mask_argument[2]={(word)&temporary,8};
        long zero[2]={0,0};
        CHECK(install(17,0x10000000UL)==0,140);
        CHECK(call(14,0,(word)&original,0,8,0,0)==0,141);
        long child=fork_();CHECK(child>=0,142);
        if(child==0)return 0;
        CHECK(call(61,child,(word)&status,0,0,0,0)==child && status==0 && handled==0,143);
        if(same(mode,"ready-pselect")) {
            CHECK(DO(1,wake_pipe[1],"R",1)==1,144);
            CHECK(call(270,64,(word)read,0,0,(word)zero,(word)mask_argument)==1 && handled==0,145);
            CHECK(call(14,2,0,(word)&current,8,0,0)==0 && current==original,146);
            CHECK(DO(0,wake_pipe[0],&byte,1)==1 && byte=='R',147);
        }
        CHECK(call(270,0,0,0,0,same(mode,"pending-pselect")?0:(word)zero,(word)mask_argument)==-4,148);
        CHECK(handled==1 && handled_signal==17,149);
        CHECK(call(14,2,0,(word)&current,8,0,0)==0 && current==original,150);
        CHECK(DO(0,wake_pipe[0],&byte,1)==1 && byte=='x',151);
    } else if (same(mode,"park-pselect") || same(mode,"park-pselect-timed")) {
        int timed=same(mode,"park-pselect-timed");
        long timeout[2]={1,0};
        word original=1UL<<(17-1), temporary=0, current=0, read[4]={1UL<<wake_pipe[0]};
        word mask_argument[2]={(word)&temporary,8};
        CHECK(install(17,0x10000000UL)==0,130);
        CHECK(call(14,0,(word)&original,0,8,0,0)==0,131);
        long child=released_child();CHECK(child>0,132);
        CHECK(call(270,64,(word)read,0,0,timed?(word)timeout:0,(word)mask_argument)==-4,133);
        CHECK(!timed || (timeout[0]==0 && timeout[1]>0 && timeout[1]<1000000000),138);
        CHECK(handled==1 && handled_signal==17,134);
        CHECK(call(14,2,0,(word)&current,8,0,0)==0 && current==original,135);
        CHECK(DO(0,wake_pipe[0],&byte,1)==1 && byte=='x',136);
        CHECK(call(61,child,(word)&status,0,0,0,0)==child && status==0,137);
    } else if (same(mode,"park-poll")) {
        struct poll_fd item={wake_pipe[0],1,0};
        CHECK(install(17,0x10000000UL)==0,30);
        long child=released_child();
        CHECK(child>0,31);
        /* poll is never restarted after a handler, even with SA_RESTART. */
        CHECK(DO(7,&item,1,-1)==-4 && handled==1,32);
        CHECK(DO(7,&item,1,-1)==1 && item.revents==1,33);
        CHECK(call(61,child,0,0,0,0,0)==child,34);
    } else if (same(mode,"park-epoll")) {
        int event[3]={1,0,0}, out[3];
        long epoll=DO(291,0,0,0), counter=DO(290,0,0,0);
        CHECK(epoll>=0 && counter>=0 && call(233,epoll,1,counter,(word)event,0,0)==0,40);
        CHECK(install(17,0)==0,41);
        long child=released_child();
        CHECK(child>0,42);
        CHECK(call(232,epoll,(word)out,1,-1,0,0)==-4 && handled==1,43);
        CHECK(call(61,child,0,0,0,0,0)==child,44);
    } else if (same(mode,"park-wait")) {
        CHECK(install(17,0)==0,50);
        long sibling=fork_();
        if (sibling==0) for (;;) __asm__ volatile("pause");
        long child=released_child();
        CHECK(sibling>0 && child>0,51);
        /* The awaited sibling never exits; the other child's SIGCHLD does. */
        CHECK(call(61,sibling,0,0,0,0,0)==-4 && handled==1,52);
        CHECK(call(61,child,0,0,0,0,0)==child,53);
        CHECK(DO(62,sibling,9,0)==0 && call(61,sibling,0,0,0,0,0)==sibling,54);
    } else if (same(mode,"park-ignored")) {
        /* A default-ignored SIGCHLD neither ends nor restarts the wait. */
        struct poll_fd item={wake_pipe[0],1,0};
        long start=now_ms();
        long child=released_child();
        CHECK(child>0,60);
        CHECK(DO(7,&item,1,1500)==0,61);
        CHECK(now_ms()-start>=1500,62);
        CHECK(call(61,child,0,0,0,0,0)==child,63);

    /* Supervisor stops and ignored signals are not sleep interruptions. */
    } else if (same(mode,"sleep-peer")) {
        long start=now_ms();
        long peer=fork_();
        if (peer==0) { char st[144]; for (;;) DO(4,"/bin/fixture",st,0); }
        CHECK(peer>0,70);
        for (int i=0;i<20;++i) {
            struct clock_time request={0,50000000};
            CHECK(DO(35,&request,0,0)==0,71);
        }
        CHECK(now_ms()-start>=1000,72);
        CHECK(DO(62,peer,9,0)==0 && call(61,peer,0,0,0,0,0)==peer,73);
    } else if (same(mode,"sleep-ignored") || same(mode,"sleep-handled")) {
        int handle=same(mode,"sleep-handled");
        struct clock_time request={0,400000000}, left={-1,-1}, brief={0,100000000};
        if (handle) { CHECK(install(17,0x10000000UL)==0,80); }
        long start=now_ms();
        long child=fork_();
        if (child==0) { DO(35,&brief,0,0); DO(60,0,0,0); }
        CHECK(child>0,81);
        long result=DO(35,&request,&left,0);
        if (handle) {
            /* nanosleep reports EINTR and the unslept time to a handler. */
            CHECK(result==-4 && handled==1 && left.seconds==0 && left.nanos>0,82);
        } else {
            CHECK(result==0 && left.seconds==-1 && now_ms()-start>=400,83);
        }
        CHECK(call(61,child,0,0,0,0,0)==child,84);

    /* The runner queues a signal while this task waits at the entry of a
       call the supervisor replaces with a private transaction. */
    } else if (same(mode,"map-signal")) {
        static char page[4096];
        page[0]='M';
        long fd=DO(2,"/work/mapped",0102,0600);
        CHECK(fd>=0 && DO(1,fd,page,4096)==4096,90);
        CHECK(install(10,0)==0,91);
        say("inject-ready\n");
        spin(400000000);
        long address=call(9,0,4096,1,2,fd,0);
        CHECK(address>0 && *(volatile char *)address=='M',92);
        CHECK(handled==1 && handled_signal==10,93);
        CHECK(DO(11,address,4096,0)==0,94);
    } else if (same(mode,"exec-signal")) {
        char *arguments[]={"fixture","exec-done",0};
        say("inject-ready\n");
        spin(400000000);
        DO(59,"/bin/fixture",arguments,0);
        return 95;

    /* The runner kills a forking parent while the supervisor is stopped
       between reserving the child and publishing it. */
    } else if (same(mode,"birth-orphan")) {
        for (;;) {
            long pid=fork_();
            if (pid==0) {
                /* Many small private pages make the kernel fork slow enough
                   for the runner to stop the supervisor inside it. */
                long size=160L<<20, memory=call(9,0,size,3,0x22,-1,0);
                if ((memory<0 && memory>-4096) || DO(28,memory,size,15)!=0) DO(231,8,0,0);
                for (long at=0;at<size;at+=4096) ((volatile char *)memory)[at]=1;
                say("orphan-ready\n");
                if (DO(0,0,&byte,1)!=1) DO(231,8,0,0);
                fork_();
                DO(231,7,0,0);
            }
            CHECK(pid>0 && call(61,pid,(word)&status,0,0,0,0)==pid,96);
            while (call(61,-1,0,0,0,0,0)>0);
            if ((status&127)==9) say("orphan-killed\n");
            else { CHECK(status==7<<8,97); say("orphan-published\n"); }
            CHECK(DO(0,0,&byte,1)==1,98);
            if (byte=='D') break;
        }

    /* Bounded race regressions: a creation whose parent dies before the
       supervisor publishes the child. They cannot force the schedule. */
    } else if (same(mode,"race-thread-exit")) {
        for (long i=0;i<300;++i) {
            long pid=fork_();
            if (pid==0) {
                spawn_thread((word)(stacks[0]+sizeof stacks[0]), &tid[0], spawner);
                spin((i%32)*400);
                DO(231,0,0,0);
            }
            CHECK(pid>0 && call(61,pid,0,0,0,0,0)==pid,100);
        }
    } else if (same(mode,"race-fork-kill")) {
        for (long i=0;i<300;++i) {
            long pid=fork_();
            if (pid==0) for (;;) {
                long child=fork_();
                if (child==0) DO(60,0,0,0);
                if (child>0) call(61,child,0,0,0,0,0);
            }
            CHECK(pid>0,110);
            spin((i%32)*800);
            CHECK(DO(62,pid,9,0)==0 && call(61,pid,0,0,0,0,0)==pid,111);
            while (call(61,-1,0,1,0,0,0)>0);
        }

    /* raise(): the handler runs in the calling thread, after the mask is restored. */
    } else if (same(mode,"raise-handled")) {
        long self=DO(186,0,0,0), process=DO(39,0,0,0);
        CHECK(install_tid(10)==0,160);
        CHECK(DO(234,process,self,0)==0 && handled==0,161);
        CHECK(DO(234,process,self,10)==0,162);
        CHECK(handled==1 && handled_signal==10 && handler_tid==self,163);
        CHECK(glibc_raise(10)==0 && handled==2,164);
        CHECK(DO(200,self,10,0)==0 && handled==3,165);
        CHECK(install(12,0)==0 && DO(200,self,12,0)==0 && handled==4 && handled_signal==12,166);
        CHECK(DO(0,wake_pipe[0],&byte,1)==1 && byte=='x',167);

    /* pthread_kill(): a sibling thread receives it, running or parked. */
    } else if (same(mode,"thread-kill")) {
        long process=DO(39,0,0,0);
        CHECK(install_tid(10)==0 && DO(293,sibling_pipe,0,0)==0,170);
        spawn_thread((word)(stacks[1]+sizeof stacks[1]), &tid[1], spinning_sibling);
        while (!tid[1]) __asm__ volatile("pause");
        int first=tid[1];
        CHECK(first!=process,171);
        CHECK(DO(234,process,first,10)==0,172);
        while (tid[1]) __asm__ volatile("pause");
        CHECK(handled==1 && handler_tid==first,173);
        spawn_thread((word)(stacks[2]+sizeof stacks[2]), &tid[2], parked_sibling);
        while (!tid[2] || !sibling_go) __asm__ volatile("pause");
        int second=tid[2];
        spin(20000000);  /* let the sibling park in its pipe read */
        CHECK(DO(200,second,10,0)==0,174);
        while (tid[2]) __asm__ volatile("pause");
        CHECK(handled==2 && handler_tid==second && sibling_result==-4,175);

    /* abort(): SIGABRT's default action ends the process with signal 6. */
    } else if (same(mode,"abort-child")) {
        long child=fork_();
        if (child==0) { glibc_raise(6); DO(60,121,0,0); }
        CHECK(child>0 && call(61,child,(word)&status,0,0,0,0)==child,180);
        CHECK((status&0x7f)==6,181);

    /* Ids only name tasks of this instance; anything else does not exist. */
    } else if (same(mode,"foreign-tid")) {
        long self=DO(186,0,0,0), process=DO(39,0,0,0);
        long host=stack[0]>2?decimal(argv[2]):0;
        CHECK(host>1,190);
        CHECK(DO(200,host,0,0)==-3 && DO(200,host,9,0)==-3,191);
        CHECK(DO(234,host,host,9)==-3 && DO(234,process,host,9)==-3,192);
        CHECK(DO(234,process,4242,10)==-3 && DO(200,4242,0,0)==-3,193);
        CHECK(DO(234,process,0,10)==-22 && DO(200,-1,10,0)==-22 && DO(234,-5,self,10)==-22,194);
        CHECK(DO(234,process,self,65)==-22,195);
        /* No group stop starts: SIGSTOP, and SIGTSTP at its default action. */
        CHECK(DO(234,process,self,19)==-95 && DO(200,self,20,0)==-95,196);
        long child=fork_();
        if (child==0) for (;;) __asm__ volatile("pause");
        CHECK(child>0,197);
        CHECK(DO(234,process,child,10)==-3 && DO(234,child,self,10)==-3,198);
        CHECK(DO(234,child,child,0)==0 && DO(200,child,10,0)==-95,199);
        CHECK(DO(234,child,child,9)==0,200);
        CHECK(call(61,child,(word)&status,0,0,0,0)==child && (status&0x7f)==9,201);
    } else return 2;
    say("held-signals: PASS\n");
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall signal_main\nmov %rax,%rdi\nmov $231,%rax\nsyscall\nud2\n");
