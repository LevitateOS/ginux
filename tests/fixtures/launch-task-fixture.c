/* Actual configured fork/wait and cross-task owned descriptor lifecycle. */
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
static void pause_forever(void) { for (;;) __asm__ volatile("pause"); }
static char buffer[8];
static volatile int fork_tid=0x1357;
static volatile int child_signal;
extern void signal_return(void);
static void child_handler(int signal, const int *info, void *context) {
    (void)context;
    child_signal=(signal==17 && info[4]==2 && info[5]==0 && info[6]==37 && DO(39,0,0,0)==1)?1:-1;
}
long task_main(word *stack)
{
    word argc=*stack;
    char **argv=(char **)(stack+1);
    char mode=argc>1 ? argv[1][0] : 'f';
    CHECK(DO(39,0,0,0)==1 && DO(186,0,0,0)==1,10);
    CHECK(DO(110,0,0,0)==0 && DO(111,0,0,0)==1,11);
    word action[4]={1,0,0,0};
    CHECK(call(13,17,(word)action,0,8,0,0)==-95,81);
    action[0]=0; action[1]=2;
    CHECK(call(13,17,(word)action,0,8,0,0)==-95,82);
    if (mode=='d') {
        CHECK(DO(80,"/source",0,0)==0,90);
        long child=DO(57,0,0,0);
        CHECK(child>=0,91);
        if (child==0) {
            CHECK(DO(80,"../work",0,0)==-95,92);
            CHECK(DO(80,"sub",0,0)==0,93);
            long fd=DO(2,"value",0,0);
            CHECK(fd>=3 && DO(0,fd,buffer,1)==1 && buffer[0]=='c',94);
            CHECK(DO(3,fd,0,0)==0,95);
            fd=DO(2,"/work/child",0102,0600);
            CHECK(fd>=3 && DO(1,fd,"x",1)==1,96);
            DO(60,0,0,0);
            __builtin_unreachable();
        }
        int status=0;
        CHECK(DO(61,child,&status,0)==child && status==0,97);
        long fd=DO(2,"value",0,0);
        CHECK(fd>=3 && DO(0,fd,buffer,1)==1 && buffer[0]=='p',98);
        CHECK(DO(3,fd,0,0)==0,99);
        fd=DO(2,"../work/child",0,0);
        CHECK(fd>=3 && DO(0,fd,buffer,1)==1 && buffer[0]=='x',100);
        CHECK(DO(3,fd,0,0)==0,101);
        CHECK(DO(80,"missing",0,0)==-2,102);
    }
    else if (mode=='f' || mode=='v' || mode=='c' || mode=='s') {
        long child=(mode=='c' || mode=='s') ? DO(56,mode=='s'?0x4111:17,0,0) : DO(mode=='v'?58:57,0,0,0);
        if (child==0) {
            CHECK(DO(39,0,0,0)==2 && DO(186,0,0,0)==2,12);
            CHECK(DO(110,0,0,0)==1 && DO(111,0,0,0)==1,13);
            DO(60,37,0,0);
            __builtin_unreachable();
        }
        CHECK(child==2,14);
        int status=0;
        CHECK(DO(61,child,&status,0)==child && status==(37<<8),15);
        CHECK(DO(61,child,&status,0)==-10,16);
        CHECK(DO(61,-1,&status,0)==-10,17);
    } else if (mode=='l' || mode=='j' || mode=='p' || mode=='h') {
        if(mode=='h') {
            word handler[4]={(word)child_handler,0x4000004,(word)signal_return,0};
            CHECK(call(13,17,(word)handler,0,8,0,0)==0,92);
        }
        long protected=call(9,0,4096,1,0x22,(word)-1,0);
        CHECK(protected>0,90);
        word address=mode=='j'?1:(mode=='p'?(word)protected:(word)&fork_tid);
        long child=call(56,0x1200011,0,0,address,0,0);
        if (!child) {
            CHECK(DO(39,0,0,0)==2 && DO(186,0,0,0)==2,83);
            if(mode=='l' || mode=='h') { CHECK(fork_tid==2,84); }
            else { CHECK(fork_tid==0x1357 && *(volatile int *)protected==0,85); }
            return 37;
        }
        CHECK(child==2 && fork_tid==0x1357 && *(volatile int *)protected==0,86);
        int status=0;
        CHECK(DO(61,child,&status,0)==child && status==(37<<8),87);
        CHECK(DO(61,child,&status,0)==-10,88);
        if(mode=='h') {
            for(word n=0;n<1000 && !child_signal;++n) DO(39,0,0,0);
            CHECK(child_signal==1,93);
        }
        CHECK(DO(11,protected,4096,0)==0,91);
    } else if (mode=='r') {
        int pipe[2]; CHECK(DO(22,pipe,0,0)==0,76);
        word limit[2]={1,1}; CHECK(DO(302,0,6,limit)==0,80);
        CHECK(DO(57,0,0,0)==-11 && DO(57,0,0,0)==-11,77);
        CHECK(call(56,0x1200011,0,0,(word)&fork_tid,0,0)==-11 && fork_tid==0x1357,89);
        CHECK(DO(1,pipe[1],"K",1)==1 && DO(0,pipe[0],buffer,1)==1 && buffer[0]=='K',78);
        CHECK(DO(3,pipe[0],0,0)==0 && DO(3,pipe[1],0,0)==0,79);
    } else if (mode=='i') {
        int send[2],reply[2];
        CHECK(DO(22,send,0,0)==0 && DO(22,reply,0,0)==0,20);
        long fd=DO(2,"/work/data",0102,0600), native=DO(2,"/input",0,0), null=DO(2,"/dev/null",2,0);
        CHECK(fd>=0 && native>=0 && null>=0,21);
        CHECK(DO(1,fd,"P",1)==1 && DO(0,native,buffer,2)==2 && buffer[0]=='a',22);
        long child=DO(57,0,0,0);
        if (child==0) {
            CHECK(DO(3,send[1],0,0)==0 && DO(3,reply[0],0,0)==0,23);
            CHECK(DO(0,send[0],buffer,1)==1 && buffer[0]=='G',24);
            CHECK(DO(1,fd,"C",1)==1 && DO(0,native,buffer,2)==2 && buffer[0]=='c',25);
            CHECK(DO(1,null,"discard",7)==7 && DO(3,null,0,0)==0,26);
            CHECK(DO(3,fd,0,0)==0 && DO(3,native,0,0)==0,27);
            CHECK(DO(1,reply[1],"R",1)==1 && DO(3,reply[1],0,0)==0,28);
            return 42;
        }
        CHECK(child==2,29);
        CHECK(DO(3,send[0],0,0)==0 && DO(3,reply[1],0,0)==0,30);
        int status=123;
        CHECK(DO(61,child,&status,1)==0 && status==123,31);
        CHECK(DO(1,send[1],"G",1)==1 && DO(3,send[1],0,0)==0,32);
        CHECK(DO(0,reply[0],buffer,1)==1 && buffer[0]=='R',33);
        CHECK(DO(0,reply[0],buffer,1)==0,34);
        CHECK(DO(61,child,1,0)==-14,35); // Must not consume the exited child.
        CHECK(DO(61,child,&status,0)==child && status==(42<<8),36);
        CHECK(DO(8,fd,0,0)==0 && DO(0,fd,buffer,8)==2 && buffer[0]=='P' && buffer[1]=='C',37);
        CHECK(DO(0,native,buffer,2)==2 && buffer[0]=='e',38);
        CHECK(DO(1,null,"still open",10)==10,39);
        CHECK(DO(3,null,0,0)==0 && DO(3,fd,0,0)==0 && DO(3,native,0,0)==0,40);
        CHECK(DO(3,reply[0],0,0)==0,41);
    } else if (mode=='k') {
        long child=DO(57,0,0,0);
        if (child==0) pause_forever();
        CHECK(child==2 && DO(62,child,0,0)==0,50);
        CHECK(DO(62,child,9,0)==0,51);
        int status;
        CHECK(DO(61,child,&status,0)==child && status==9,52);
        CHECK(DO(62,child,0,0)==-3 && DO(62,-1,9,0)==-95,53);
    } else if (mode=='b') {
        int pipe[2];
        CHECK(DO(22,pipe,0,0)==0,60);
        long children[15];
        for (word i=0;i<15;++i) {
            long child=DO(57,0,0,0);
            if (child==0) { CHECK(DO(0,pipe[0],buffer,1)==1,61); return 0; }
            CHECK(child>1,62);
            children[i]=child;
        }
        CHECK(DO(57,0,0,0)==-11,63);
        CHECK(DO(56,17|0x800000,0,0)==-38,64); // CLONE_UNTRACED
        CHECK(DO(56,17|0x20000000,0,0)==-38,65); // CLONE_NEWPID
        CHECK(DO(56,17|0x400,0,0)==-38,66); // CLONE_FILES
        for (word i=0;i<15;++i) CHECK(DO(62,children[i],9,0)==0,67);
        for (word i=0;i<15;++i) { int status; CHECK(DO(61,children[i],&status,0)==children[i] && status==9,68); }
        long child=DO(57,0,0,0);
        if (child==0) return 19;
        int status;
        CHECK(child>16 && DO(61,child,&status,0)==child && status==(19<<8),69);
    } else if (mode=='o') {
        int pipe[2]; CHECK(DO(22,pipe,0,0)==0,70);
        long child=DO(57,0,0,0);
        if (child==0) {
            long grandchild=DO(57,0,0,0);
            if (grandchild==0) { CHECK(DO(1,pipe[1],"ready\n",6)==6,71); pause_forever(); }
            CHECK(grandchild==3,72);
            return 0;
        }
        CHECK(child==2 && DO(0,pipe[0],buffer,6)==6,73);
        int status;
        CHECK(DO(61,child,&status,0)==child && status==0,74);
        CHECK(DO(62,3,9,0)==0 && DO(61,3,&status,0)==3 && status==9,75);
    } else if (mode=='t') {
        long child=DO(57,0,0,0);
        if (child==0) {
            long grandchild=DO(57,0,0,0);
            if (grandchild==0) { DO(1,1,"ready\n",6); pause_forever(); }
            pause_forever();
        }
        pause_forever(); // Runner kills root with two descendants still alive.
    } else return 99;
    DO(1,1,"owned-tasks: PASS\n",18);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall task_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
__asm__(".global signal_return\nsignal_return:\nmov $15,%rax\nsyscall\nud2\n");
