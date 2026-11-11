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
static volatile int packet_signal_count, packet_signal_tid;
static volatile long packet_write_result, packet_nosignal_result;
void packet_signal_return(void);
__asm__(".global packet_signal_return\npacket_signal_return:\nmov $15,%eax\nsyscall\nud2\n");
static void packet_sigpipe(int signal) {
    if(signal==13) { ++packet_signal_count; packet_signal_tid=(int)DO(186,0,0,0); }
}
static long packet_writer(void) {
    while(!gate) {
        long result=DO(202,&gate,0,0);
        if(result!=0 && result!=-11 && result!=-4) { error=194; return 0; }
    }
    packet_write_result=DO(1,pair[0],"X",1);
    packet_nosignal_result=call(44,pair[0],(word)"Y",1,0x4000,0,0);
    return 0;
}
static volatile word mutable_path[2]={0x6465776f6c6c612fUL,0};
static volatile int path_done;
static long path_writer(void) {
    while(!path_done) {
        mutable_path[0]=0x6465776f6c6c612fUL;
        mutable_path[0]=0x68682f6b726f772fUL;
    }
    return 0;
}
static volatile word path_scratch_rsp;
static volatile int path_scratch_ready;
static long path_scratch_writer(void) {
    path_scratch_ready=1;
    while(!path_done) {
        word rsp=path_scratch_rsp;
        if(!rsp) continue;
        volatile word *slot=(volatile word *)(rsp-512);
        // Replace the supervisor's canonical path with hidden image /work/hh.
        slot[0]=0x68682f6b726f772fUL;
        ((volatile char *)slot)[8]=0;
    }
    return 0;
}
// Publish the exact syscall stack pointer used by Rewrite::prepare.
__attribute__((noinline)) static long open_scratch(void) {
    word number=2;
    __asm__ volatile("mov %%rsp,%1\n\tsyscall" : "+a"(number), "=m"(path_scratch_rsp)
                     : "D"((word)"/./allowed"), "S"((word)0), "d"((word)0)
                     : "rcx", "r11", "memory");
    return (long)number;
}
static volatile word shared_action[4];
static volatile int action_ready, action_flags_mode;
static long sigchld_writer(void) {
    action_ready=1;
    while(!path_done) {
        if(action_flags_mode) { shared_action[1]=0; shared_action[1]=2; }
        else { shared_action[0]=0; shared_action[0]=1; }
    }
    return 0;
}
static volatile word *race_tid_page;
static volatile int race_ready, race_done;
static long tid_protect_writer(void) {
    race_ready=1;
    while(!race_done) {
        if(DO(10,race_tid_page,4096,1)!=0 || DO(10,race_tid_page,4096,3)!=0) { error=160; break; }
    }
    DO(10,race_tid_page,4096,3);
    return 0;
}
static volatile int private_done, private_checks;
static long private_fd_probe(void) {
    char byte;
    while (!private_done) {
        for (word fd=5;fd<8;++fd) {
            if (DO(5,fd,&byte,0)!=-9 || DO(72,fd,1,0)!=-9 ||
                DO(3,fd,0,0)!=-9 || call(9,0,4096,1,2,fd,0)!=-9) {
                error=108;
                return 0;
            }
        }
        ++private_checks;
    }
    return 0;
}
static volatile word victim_rsp;
static volatile int scratch_ready;
static long scratch_writer(void) {
    scratch_ready=1;
    while(!path_done) {
        word address=victim_rsp;
        if(!address) continue;
        volatile word *frame=(volatile word *)(address-512);
        if(frame[6]==address-512+96 && frame[9]==24) frame[6]=1;
    }
    return 0;
}
long spawn_thread(word top, volatile int *tid, long (*fn)(void));
__asm__(".global spawn_thread\nspawn_thread:\n"
        "mov %rdx,-16(%rdi)\nmov %rsi,%rdx\nmov %rsi,%r10\nmov %rdi,%rsi\nsub $16,%rsi\n"
        "xor %r8d,%r8d\nmov thread_flags(%rip),%edi\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 1f\n"
        "xor %ebp,%ebp\ncall *(%rsp)\nmov %rax,%rdi\nmov $60,%eax\nsyscall\nud2\n1:ret\n");
long spawn_thread_split(word top, volatile int *parent_tid, volatile int *child_tid, long (*fn)(void));
__asm__(".global spawn_thread_split\nspawn_thread_split:\n"
        "mov %rcx,-16(%rdi)\nmov %rdx,%r10\nmov %rsi,%rdx\nmov %rdi,%rsi\nsub $16,%rsi\n"
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
static long go_thread(void) {
    char signal_stack[16384];
    word alt[3]={(word)signal_stack,0,sizeof signal_stack};
    word pending=0;
    if(DO(131,alt,0,0)!=0 || DO(127,&pending,8,0)!=0 || DO(186,0,0,0)!=2) error=210;
    gate=1; DO(202,&gate,1,1);
    return 0;
}
static long quick(void) { return 0; }
static volatile long nested_bad, nested_good, nested_seen_tid, nested_seen_parent;
static long nested_quick(void) {
    nested_seen_tid=DO(186,0,0,0);
    nested_seen_parent=DO(110,0,0,0);
    return 0;
}
static long nested_birth(void) {
    long page=call(9,0,4096,3,0x22,(word)-1,0);
    if(page<=0) { error=178; return 0; }
    *(volatile int *)page=0x44332211;
    if(DO(10,page,4096,1)!=0) { error=179; return 0; }
    nested_bad=spawn_thread((word)(stacks[1]+sizeof stacks[1]),(volatile int *)page,nested_quick);
    if(DO(10,page,4096,3)!=0) { error=180; return 0; }
    if(nested_bad!=-14 || *(volatile int *)page!=0x44332211) { error=181; return 0; }
    nested_good=spawn_thread((word)(stacks[1]+sizeof stacks[1]),&tid[1],nested_quick);
    if(nested_good>1) join(1);
    if(DO(11,page,4096,0)!=0) error=182;
    return 0;
}
static volatile long child_pointer_result, child_pointer_tid;
static volatile int child_pointer_done;
static long child_pointer_quick(void) {
    child_pointer_tid=DO(186,0,0,0);
    child_pointer_done=1;
    DO(202,&child_pointer_done,1,1);
    return 0;
}
static long nested_child_pointer(void) {
    long page=call(9,0,4096,3,0x22,(word)-1,0);
    if(page<=0) { error=186; return 0; }
    *(volatile int *)page=0x44332211;
    if(DO(10,page,4096,1)!=0) { error=187; return 0; }
    child_pointer_result=spawn_thread_split((word)(stacks[1]+sizeof stacks[1]),&tid[1],
                                            (volatile int *)page,child_pointer_quick);
    if(child_pointer_result<0) { error=188; return 0; }
    while(!child_pointer_done) {
        long result=DO(202,&child_pointer_done,0,0);
        if(result!=0 && result!=-11 && result!=-4) { error=189; return 0; }
    }
    if(child_pointer_result!=3 || child_pointer_tid!=3 || tid[1]!=3 ||
       *(volatile int *)page!=0x44332211) error=190;
    if(DO(11,page,4096,0)!=0) error=191;
    return 0;
}
static long shared_umask(void) {
    if(DO(95,0077,0,0)!=0022)error=91;
    return 0;
}
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
__attribute__((noinline)) static long fixed_code_mapping(void) {
    return call(9,(word)fixed_code_mapping & ~4095UL,4096,1,0x12,3,0);
}
__attribute__((noinline)) static long fixed_stack_mapping(void) {
    word stack;
    __asm__ volatile("mov %%rsp,%0":"=r"(stack));
    return call(9,(stack-512)&~4095UL,4096,1,0x12,3,0);
}
static long nonleader_mapping(void) {
    long mapped=call(9,0,4096,1,2,3,0);
    if(mapped<=0 || *(volatile char *)mapped!='M') { error=114; return 0; }
    if(DO(11,mapped,4096,0)!=0) error=115;
    return 0;
}
static long after_leader_mapping(void) {
    char input;
    if(DO(0,0,&input,1)!=1 || input!='G') return 119;
    if(DO(77,3,4096,0)!=0 || DO(1,3,"M",1)!=1) return 120;
    long mapped=call(9,0,4096,1,2,3,0);
    if(mapped<=0 || *(volatile char *)mapped!='M' || DO(11,mapped,4096,0)!=0) return 121;
    DO(1,1,"owned-threads: PASS\n",20);
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
    if (mode=='G') { thread_flags=0xd0f00; mode='r'; }
    int pi=0;
    CHECK(DO(202,&pi,6,0)==-1 && pi==0,69);
    CHECK(DO(2,"/work/shared",0102,0600)==3 && DO(2,"/input",0,0)==4,10);
    if (mode=='g') {
        thread_flags=0xd0f00;
        tid[0]=0x12345678;
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],go_thread)==2,211);
        while(!gate) { long n=DO(202,&gate,0,0); CHECK(n==0 || n==-11 || n==-4,212); }
        CHECK(!error && tid[0]==0x12345678 && DO(39,0,0,0)==1,213);
    } else if (mode=='P') {
        word action[4]={(word)packet_sigpipe,0x04000000,(word)packet_signal_return,0};
        CHECK(call(13,13,(word)action,0,8,0,0)==0,195);
        CHECK(call(53,1,5,0,(word)pair,0,0)==0 && pair[0]==5 && pair[1]==6,196);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],packet_writer)==2,197);
        CHECK(DO(3,pair[1],0,0)==0,198);
        gate=1;CHECK(DO(202,&gate,1,1)>=0,199);
        join(0);
        CHECK(!error && packet_write_result==-32 && packet_nosignal_result==-32,201);
        CHECK(packet_signal_count==1 && packet_signal_tid==2,202);
        CHECK(DO(3,pair[0],0,0)==0,203);
    } else if (mode=='C') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],nested_child_pointer)==2,192);
        join(0);
        CHECK(!error && child_pointer_result==3 && child_pointer_tid==3 &&
              tid[0]==0 && tid[1]==3,193);
    } else if (mode=='N') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],nested_birth)==2,183);
        join(0);
        CHECK(!error && nested_bad==-14 && nested_good==3 &&
              nested_seen_tid==3 && nested_seen_parent==0 && tid[0]==0 && tid[1]==0,184);
    } else if (mode=='B') {
        long mapped=call(9,0,8192,3,0x22,(word)-1,0);
        CHECK(mapped>0,169);
        volatile unsigned char *split=(volatile unsigned char *)(mapped+4094);
        split[0]=0x11; split[1]=0x22; split[2]=0x33; split[3]=0x44;
        CHECK(DO(10,mapped+4096,4096,0)==0,170);
        long inaccessible=spawn_thread((word)(stacks[0]+sizeof stacks[0]),(volatile int *)split,quick);
        CHECK(DO(10,mapped+4096,4096,3)==0,171);
        CHECK(inaccessible==-14 && split[0]==0x11 && split[1]==0x22 && split[2]==0x33 && split[3]==0x44,172);
        CHECK(DO(10,mapped,4096,1)==0,173);
        long partial=spawn_thread((word)(stacks[0]+sizeof stacks[0]),(volatile int *)split,quick);
        CHECK(DO(10,mapped,4096,3)==0,174);
        CHECK(partial==-14 && split[0]==0x11 && split[1]==0x22 && split[2]==0x33 && split[3]==0x44,175);
        long valid=spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],quick);
        join(0);
        CHECK(!error && valid==2 && tid[0]==0,177);
    } else if (mode=='T' || mode=='U') {
        long page=call(9,0,4096,3,0x22,(word)-1,0);
        CHECK(page>0,161);
        race_tid_page=(volatile word *)page;
        if(mode=='T') {
            CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],tid_protect_writer)==2,162);
            while(!race_ready) __asm__ volatile("pause");
        }
        word successes=0, faults=0, capacity=0;
        for(word i=1;i<=16;++i) {
            long child=spawn_thread((word)(stacks[i]+sizeof stacks[i]),(volatile int *)race_tid_page,quick);
            if(child>1) ++successes;
            else if(child==-14) ++faults;
            else if(child==-11) ++capacity;
            else { error=163; break; }
            for(word j=0;j<32;++j) DO(39,0,0,0);
        }
        race_done=1;
        if(mode=='T') join(0);
        CHECK(DO(10,race_tid_page,4096,3)==0,164);
        CHECK(successes+faults+capacity==16,165);
        CHECK(!error && spawn_thread((word)(stacks[17]+sizeof stacks[17]),
                                    (volatile int *)race_tid_page,quick)>1,166);
    } else if (mode=='Z' || mode=='z' || mode=='V') {
        word successful=0, rejected=0, exposed=0;
        if(mode=='z' || mode=='V') {
            action_flags_mode=(mode=='V');
            CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],sigchld_writer)==2,150);
            while(!action_ready) __asm__ volatile("pause");
        }
        for(word i=0;i<(mode=='Z'?64:1024) && !exposed;++i) {
            long result=call(13,17,(word)shared_action,0,8,0,0);
            word old[4]={0,0,0,0};
            long query=call(13,17,0,(word)old,8,0,0);
            if(query!=0 || (result!=0 && result!=-95)) { error=151; break; }
            if(result==0) ++successful; else ++rejected;
            if(result==0 && (old[0]==1 || (old[1]&2))) exposed=1;
        }
        path_done=1;
        if(mode=='z' || mode=='V') join(0);
        word safe[4]={0,0,0,0};
        CHECK(call(13,17,(word)safe,0,8,0,0)==0,152);
        CHECK(successful+rejected==(mode=='Z'?64:1024),153);
        CHECK(!error && !exposed,154);
    } else if (mode=='X') {
        long control=open_scratch();
        CHECK(control>=5,200);
        char control_byte=0;
        CHECK(DO(0,control,&control_byte,1)==1 && control_byte=='A',201);
        CHECK(DO(3,control,0,0)==0,202);
        path_scratch_rsp=0;
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],path_scratch_writer)==2,203);
        while(!path_scratch_ready) __asm__ volatile("pause");
        int exposed=0;
        word allowed=0;
        for(word i=0;i<2048 && !exposed && !error;++i) {
            long fd=open_scratch();
            path_scratch_rsp=0;
            if(fd>=5) {
                char value=0;
                long read=DO(0,fd,&value,1);
                if(read==1 && value=='A') ++allowed;
                else if(read==1 && value=='S') exposed=1;
                else error=207;
                if(DO(3,fd,0,0)!=0) error=208;
            }
        }
        path_done=1;
        join(0);
        CHECK(!error,204);
        CHECK(!exposed,205);
        CHECK(allowed>0,206);
    } else if (mode=='x') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],path_writer)==2,98);
        int exposed=0;
        for(word i=0;i<2048 && !exposed;++i) {
            long fd=DO(2,mutable_path,0,0);
            if(fd>=5) {
                char value=0;
                if(DO(0,fd,&value,1)==1 && value=='S') exposed=1;
                DO(3,fd,0,0);
            }
        }
        path_done=1;
        join(0);
        CHECK(!error,100);
        CHECK(!exposed,99);
    } else if (mode=='y') {
        CHECK(DO(77,3,4096,0)==0 && DO(1,3,"M",1)==1,101);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],path_writer)==2,102);
        long mapped=call(9,0,4096,1,2,3,0);
        path_done=1;
        join(0);
        CHECK(mapped>0 && *(volatile char *)mapped=='M' && DO(11,mapped,4096,0)==0 && !error,103);
    } else if (mode=='a') {
        char token;
        volatile word sentinel=0x71efbb003a5cd029UL;
        CHECK(DO(77,3,4096,0)==0 && DO(1,3,"M",1)==1,134);
        CHECK(DO(1,1,"pair-ready\n",11)==11 && DO(0,0,&token,1)==1 && token=='A',135);
        CHECK(call(9,0,4096,1,2,3,0)==-24,136);
        CHECK(sentinel==0x71efbb003a5cd029UL,137);
        CHECK(DO(1,1,"pair-failed\n",12)==12 && DO(0,0,&token,1)==1 && token=='G',138);
        long mapped=call(9,0,4096,1,2,3,0);
        CHECK(mapped>0 && *(volatile char *)mapped=='M' && DO(11,mapped,4096,0)==0,139);
    } else if (mode=='w') {
        char token;
        volatile word sentinel=0x9be751ac6732d004UL;
        CHECK(DO(77,3,4096,0)==0 && DO(1,3,"M",1)==1,128);
        CHECK(DO(1,1,"before-map\n",11)==11 && DO(0,0,&token,1)==1 && token=='A',129);
        long failed=call(9,0,4096,1,2,3,~4095UL);
        if(failed>=0) { DO(11,failed,4096,0); return 130; }
        CHECK(sentinel==0x9be751ac6732d004UL,131);
        CHECK(DO(1,1,"after-map\n",10)==10 && DO(0,0,&token,1)==1 && token=='G',132);
        long mapped=call(9,0,4096,1,2,3,0);
        CHECK(mapped>0 && *(volatile char *)mapped=='M' && DO(11,mapped,4096,0)==0,133);
    } else if (mode=='q') {
        volatile word sentinel=0x517ac2dd5678beefUL;
        CHECK(DO(77,3,4096,0)==0 && DO(1,3,"M",1)==1,124);
        CHECK(fixed_code_mapping()==-95,125);
        CHECK(fixed_stack_mapping()==-95 && sentinel==0x517ac2dd5678beefUL,126);
        long mapped=call(9,0,4096,1,2,3,0);
        CHECK(mapped>0 && *(volatile char *)mapped=='M' && DO(11,mapped,4096,0)==0,127);
    } else if (mode=='n') {
        CHECK(DO(77,3,4096,0)==0 && DO(1,3,"M",1)==1,116);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],nonleader_mapping)==2,117);
        join(0);
        CHECK(!error && tid[0]==0,118);
    } else if (mode=='v') {
        CHECK(DO(77,3,4096,0)==0 && DO(1,3,"M",1)==1,109);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],private_fd_probe)==2,110);
        while(private_checks<32 && !error) __asm__ volatile("pause");
        CHECK(!error,111);
        for(word i=0;i<64 && !error;++i) {
            long mapped=call(9,0,4096,1,2,3,0);
            if(mapped<=0 || *(volatile char *)mapped!='M' || DO(11,mapped,4096,0)!=0) {
                error=112;
                break;
            }
        }
        private_done=1;
        join(0);
        CHECK(!error && private_checks>=32,113);
    } else if (mode=='k') {
        CHECK(DO(77,3,4096,0)==0 && DO(1,3,"M",1)==1,104);
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],scratch_writer)==2,105);
        while(!scratch_ready) __asm__ volatile("pause");
        __asm__ volatile("mov %%rsp,%0":"=r"(victim_rsp));
        long mapped=call(9,0,4096,1,2,3,0);
        path_done=1;
        join(0);
        CHECK(mapped>0 && *(volatile char *)mapped=='M' && !error,106);
        CHECK(DO(11,mapped,4096,0)==0,107);
    } else if (mode=='u') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],shared_umask)==2,92);
        join(0);CHECK(!error && DO(95,0022,0,0)==0077,93);
    } else if (mode=='t') {
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
    } else if (mode=='j') {
        CHECK(spawn_thread((word)(stacks[0]+sizeof stacks[0]),&tid[0],after_leader_mapping)==2,122);
        CHECK(DO(1,1,"leader-ready\n",13)==13,123);
        return 0;
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
