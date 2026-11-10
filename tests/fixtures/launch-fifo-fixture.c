/* Named FIFO namespace and rendezvous checks, also runnable on native Linux. */
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
#define CHECK(expr,code) do { if (!(expr)) return code; } while (0)
static unsigned char statbuf[256] __attribute__((aligned(8)));
static unsigned char data[65536];
static word inode(void) { return *(word *)(statbuf + 8); }
static unsigned mode(void) { return *(unsigned *)(statbuf + 24); }
static long open_fifo(const char *path, unsigned flags) { return DO(2,path,flags,0600); }
static long close_fd(long fd) { return DO(3,fd,0,0); }
static void descriptor_path(char *path, unsigned fd)
{
    const char prefix[]="/dev/fd/";
    for(unsigned i=0;i<sizeof(prefix)-1;++i)path[i]=prefix[i];
    char digits[10];unsigned count=0, offset=sizeof(prefix)-1;
    do {digits[count++]=(char)('0'+fd%10);fd/=10;} while(fd);
    while(count)path[offset++]=digits[--count];
    path[offset]=0;
}
static long metadata(void)
{
    CHECK(DO(95,0027,0,0)>=0,10);
    CHECK(call(259,-100,(word)"fifo",010666,0,0,0)==0,11);
    CHECK(DO(6,"fifo",statbuf,0)==0 && mode()==010640,12);
    word original=inode();
    CHECK(DO(133,"fifo",010600,0)==-17,13);
    for(int i=0;i<80;++i)CHECK(open_fifo("fifo",1|04000)==-6,14);
    long reader=open_fifo("fifo",04000);CHECK(reader>=3,15);
    struct { int fd; short events,revents; } poller={(int)reader,1,0};
    CHECK(DO(7,&poller,1,0)==0 && DO(0,reader,data,1)==0,16);
    long writer=open_fifo("fifo",1|04000);CHECK(writer>=3,17);
    CHECK(DO(5,reader,statbuf,0)==0 && inode()==original && mode()==010640,18);
    CHECK(call(262,writer,(word)"",(word)statbuf,0x1000,0,0)==0 && inode()==original,19);
    int queued=-1;
    CHECK(DO(1,writer,"hello",5)==5 && DO(16,reader,0x541b,&queued)==0 && queued==5,20);
    CHECK(DO(0,reader,data,8)==5 && data[4]=='o',20);
    CHECK(DO(0,reader,data,1)==-11,21);
    long other=open_fifo("fifo",04000), alias=DO(32,reader,0,0);
    CHECK(other>=3 && alias>=3 && DO(72,alias,4,0)==0,22);
    CHECK((DO(72,reader,3,0)&04000)==0 && (DO(72,other,3,0)&04000)!=0,23);
    CHECK(DO(72,reader,4,04000)==0,24);
    CHECK(DO(91,writer,0600,0)==0 && DO(4,"fifo",statbuf,0)==0 && mode()==010600,25);
    CHECK(DO(86,"fifo","alias",0)==0 && DO(88,"fifo","symlink",0)==0,26);
    long through_link=open_fifo("symlink",2|04000);CHECK(through_link>=3,27);
    CHECK(DO(5,through_link,statbuf,0)==0 && inode()==original,28);
    long directory=open_fifo(".",0200000);CHECK(directory>=3,49);
    char child_path[32];descriptor_path(child_path,(unsigned)directory);
    unsigned end=0;while(child_path[end])++end;
    const char tail[]="/fifo";
    for(unsigned i=0;i<sizeof(tail);++i)child_path[end+i]=tail[i];
    long via_directory=open_fifo(child_path,04000);
    CHECK(via_directory>=3 && DO(0,via_directory,data,1)==-11,49);
    CHECK(close_fd(via_directory)==0 && close_fd(directory)==0,49);
    long path=open_fifo("fifo",010000000);CHECK(path>=3,29);
    CHECK(DO(5,path,statbuf,0)==0 && inode()==original && DO(0,path,data,1)==-9,30);
    CHECK(close_fd(path)==0,31);
    CHECK(DO(82,"fifo","moved",0)==0 && DO(87,"moved",0,0)==0 && DO(87,"alias",0,0)==0,32);
    CHECK(DO(5,writer,statbuf,0)==0 && inode()==original && *(word *)(statbuf+16)==0,33);
    char fd_path[32];descriptor_path(fd_path,(unsigned)writer);
    for(int i=0;i<80;++i) {
        long reopened=open_fifo(fd_path,2|04000);CHECK(reopened>=3,47);
        CHECK(DO(5,reopened,statbuf,0)==0 && inode()==original && close_fd(reopened)==0,48);
    }
    CHECK(DO(133,"fifo",010600,0)==0,34);
    long replacement=open_fifo("fifo",2|04000);CHECK(replacement>=3,35);
    CHECK(DO(5,replacement,statbuf,0)==0 && inode()!=original,36);
    CHECK(DO(1,writer,"old",3)==3 && DO(0,replacement,data,3)==-11,37);
    CHECK(DO(0,reader,data,3)==3 && data[0]=='o',38);
    CHECK(close_fd(writer)==0 && close_fd(through_link)==0,39);
    CHECK(DO(7,&poller,1,0)==1 && (poller.revents&16) && DO(0,reader,data,1)==0,40);
    CHECK(close_fd(alias)==0 && close_fd(reader)==0 && close_fd(other)==0,41);
    CHECK(DO(1,replacement,"discard",7)==7 && close_fd(replacement)==0,42);
    replacement=open_fifo("fifo",2|04000);
    CHECK(replacement>=3 && DO(0,replacement,data,1)==-11,43);
    CHECK(DO(8,replacement,0,0)==-29,44);
    CHECK(close_fd(replacement)==0 && DO(87,"symlink",0,0)==0,45);
    CHECK(DO(86,"fifo","snapshot-link",0)==0,46);
    return 0;
}
static long blocking(void)
{
    CHECK(DO(133,"fifo",010600,0)==0,50);
    for(int side=0;side<2;++side) for(int attempt=0;attempt<12;++attempt) {
        long child=DO(57,0,0,0);CHECK(child>=0,51);
        if(child==0) {
            long endpoint=open_fifo("fifo",side);
            DO(60,endpoint>=3 && close_fd(endpoint)==0?0:52,0,0);
            __builtin_unreachable();
        }
        long endpoint=open_fifo("fifo",1-side);CHECK(endpoint>=3,53);
        CHECK(close_fd(endpoint)==0,54);
        int status=-1;
        CHECK(DO(61,child,&status,0)==child && status==0,55);
    }
    /* A write larger than PIPE_BUF must finish across reader wakeups. */
    long child=DO(57,0,0,0);CHECK(child>=0,56);
    if(child==0) {
        long writer=open_fifo("fifo",1);
        for(word i=0;i<sizeof(data);++i)data[i]=(unsigned char)(i%251);
        DO(60,writer>=3 && DO(1,writer,data,sizeof(data))==(long)sizeof(data)?0:57,0,0);
        __builtin_unreachable();
    }
    long reader=open_fifo("fifo",0);CHECK(reader>=3,58);
    word total=0;
    for(;;){long count=DO(0,reader,data,97);CHECK(count>=0,59);if(count==0)break;
        for(long i=0;i<count;++i)CHECK(data[i]==(unsigned char)((total+(word)i)%251),60);
        total+=(word)count;}
    int status=-1;
    CHECK(total==sizeof(data) && DO(61,child,&status,0)==child && status==0,61);
    CHECK(close_fd(reader)==0,62);
    return 0;
}
static char thread_stack[16384] __attribute__((aligned(16)));
static volatile int thread_tid;
static volatile long thread_result;
long spawn_thread(word top, volatile int *tid, long (*fn)(void));
__asm__(".global spawn_thread\nspawn_thread:\n"
        "mov %rdx,-16(%rdi)\nmov %rsi,%rdx\nmov %rsi,%r10\nmov %rdi,%rsi\nsub $16,%rsi\n"
        "xor %r8d,%r8d\nmov $0x3d0f00,%edi\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 1f\n"
        "xor %ebp,%ebp\ncall *(%rsp)\nmov %rax,%rdi\nmov $60,%eax\nsyscall\nud2\n1:ret\n");
static long reader_thread(void)
{
    long fd=open_fifo("fifo",0);
    thread_result=fd;
    if(fd>=0)close_fd(fd);
    return 0;
}
static long shared_table(void)
{
    CHECK(DO(133,"fifo",010600,0)==0,90);
    CHECK(spawn_thread((word)(thread_stack+sizeof(thread_stack)),&thread_tid,reader_thread)>0,91);
    /* Runner releases this console read only after observing the FIFO park. */
    CHECK(DO(0,0,data,1)==1,92);
    long fd=open_fifo("ordinary",0102);CHECK(fd==4,93);
    CHECK(DO(33,fd,3,0)==-16 && close_fd(3)==-9,94);
    long child=DO(57,0,0,0);CHECK(child>=0,95);
    if(child==0) {
        long next=open_fifo("ordinary",0);
        DO(60,next==3?0:96,0,0);__builtin_unreachable();
    }
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,97);
    long writer=open_fifo("fifo",1);CHECK(writer==5,98);
    while(thread_tid){int tid=thread_tid;if(tid)DO(202,&thread_tid,0,tid);}
    CHECK(thread_result==3 && close_fd(writer)==0 && close_fd(fd)==0,99);
    return 0;
}
static volatile int interrupted;
void signal_return(void);
__asm__(".global signal_return\nsignal_return:\nmov $15,%eax\nsyscall\nud2\n");
static void signal_handler(int signal) { interrupted=signal; }
static long interrupt_open(void)
{
    word action[4]={(word)signal_handler,0x04000000,(word)signal_return,0};
    CHECK(call(13,17,(word)action,0,8,0,0)==0,100);
    CHECK(DO(133,"fifo",010600,0)==0,101);
    long child=DO(57,0,0,0);CHECK(child>=0,105);
    if(child==0) {
        DO(60,DO(0,0,data,1)==1?0:106,0,0);__builtin_unreachable();
    }
    /* Child completion uses the supervisor's supported pending-signal wake. */
    CHECK(open_fifo("fifo",0)==-4 && interrupted==17,102);
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,107);
    CHECK(open_fifo("fifo",1|04000)==-6,103);
    long fd=open_fifo("fifo",2|04000);CHECK(fd==3 && close_fd(fd)==0,104);
    return 0;
}
long fifo_main(word *stack)
{
    char **argv=(char **)(stack+1);
    CHECK(*stack>=3 && DO(80,argv[1],0,0)==0,1);
    long result=0;
    if(argv[2][0]=='b') result=blocking();
    else if(argv[2][0]=='s') result=shared_table();
    else if(argv[2][0]=='i') result=interrupt_open();
    else if(argv[2][0]=='r') {
        CHECK(DO(4,"fifo",statbuf,0)==0 && mode()==010600,70);
        word saved=inode();
        CHECK(DO(4,"snapshot-link",statbuf,0)==0 && inode()==saved,71);
        long fd=open_fifo("fifo",2|04000);CHECK(fd>=3 && DO(0,fd,data,1)==-11,72);
        CHECK(close_fd(fd)==0,73);
    } else if(argv[2][0]=='p') {
        CHECK(DO(133,"fifo",010600,0)==0,80);
        (void)open_fifo("fifo",argv[2][1]=='w'?1:0);
        return 81;
    } else result=metadata();
    if(result)return result;
    DO(1,1,"owned-fifos: PASS\n",18);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\ncall fifo_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\n");
