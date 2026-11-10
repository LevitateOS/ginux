/* Real configured public-descriptor readiness, timers and peer wakeups. */
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
struct pollfd { int fd; unsigned short events, revents; };
static const struct pollfd readonly_poll = {123,0,0};
static char buffer[4096];
static char console_data[10003];
static long query(int fd, unsigned short events, unsigned short expected)
{
    struct pollfd entry={fd,events,0xffff};
    return DO(7,&entry,1,0)==(expected!=0) && entry.fd==fd && entry.events==events && entry.revents==expected;
}
long poll_main(word *stack)
{
    char **argv=(char **)(stack+1);
    char mode=*stack>1 ? argv[1][0] : 'a';
    int pipe[2]; CHECK(DO(293,pipe,04000,0)==0,10);
    if (mode=='L') {
        for(word i=0;i<sizeof console_data;++i)console_data[i]='A'+i%26;
        long alias=DO(32,1,0,0);CHECK(alias>=3,102);
        long written=DO(1,1,console_data,sizeof console_data);CHECK(written==4096,103);
        while((word)written<sizeof console_data) {
            long n=DO(1,alias,console_data+written,sizeof console_data-written);
            CHECK(n>0 && n<=4096,104);written+=n;
        }
        CHECK(DO(3,alias,0,0)==0,105);
    } else if (mode=='C') {
        CHECK(DO(1,1,console_data,sizeof console_data)==-1,106);
        long alias=DO(32,1,0,0);CHECK(alias>=3,107);
        CHECK(DO(1,alias,console_data,sizeof console_data)==-1 && DO(3,alias,0,0)==0,108);
        return 0;
    } else if (mode=='s') {
        word read[4]={1UL<<pipe[0]}, write[4]={1UL<<pipe[1]}, except[4]={1UL<<pipe[0]};
        long timeout[2]={0,0};
        CHECK(call(270,64,(word)read,(word)write,(word)except,(word)timeout,0)==1,80);
        CHECK(read[0]==0 && write[0]==(1UL<<pipe[1]) && except[0]==0,81);
        CHECK(DO(1,pipe[1],"S",1)==1,82);
        read[0]=1UL<<pipe[0]; write[0]=1UL<<pipe[1];
        CHECK(call(270,64,(word)read,(word)write,0,(word)timeout,0)==2,83);
        CHECK(read[0]==(1UL<<pipe[0]) && write[0]==(1UL<<pipe[1]),84);
        read[0]=1UL<<63;
        CHECK(call(270,64,(word)read,0,0,(word)timeout,0)==-9,85);
        CHECK(call(270,64,1,0,0,(word)timeout,0)==-14,86);
        CHECK(call(270,257,0,0,0,(word)timeout,0)==-22,87);
        word mask_argument[2]={1,8};
        CHECK(call(270,0,0,0,0,(word)timeout,(word)mask_argument)==-14,88);
        read[0]=1UL<<pipe[0];
        CHECK(call(270,64,(word)read,0,0,(word)timeout,0)==1 && read[0]==(1UL<<pipe[0]),89);
        timeout[0]=300;timeout[1]=1;
        CHECK(call(270,0,0,0,0,(word)timeout,0)==-22,100);
        timeout[0]=0;timeout[1]=1000000000;
        CHECK(call(270,0,0,0,0,(word)timeout,0)==-22,101);
        timeout[1]=60000000;
        CHECK(call(270,0,0,0,0,(word)timeout,0)==0 && timeout[0]==0 && timeout[1]==0,90);
    } else if (mode=='S') {
        long null=DO(2,"/dev/null",2,0);CHECK(null>=3,91);
        CHECK(DO(1,pipe[1],"S",1)==1,92);
        CHECK(call(275,pipe[0],0,null,0,1,0)==-22,93);
        CHECK(DO(0,pipe[0],buffer,1)==1 && buffer[0]=='S',94);
        CHECK(call(275,123,0,null,0,1,0)==-9,95);
        CHECK(call(275,pipe[0],0,123,0,1,0)==-9,96);
        CHECK(DO(3,null,0,0)==0,97);
    } else if (mode=='D') {
        long timeout[2]={0,0};
        CHECK(call(270,0,0,0,0,(word)timeout,0)==-1,98);
        CHECK(call(275,pipe[0],0,pipe[1],0,1,0)==-1,99);
    } else if (mode=='o') {
        if(argv[1][8]=='-') {
            CHECK(DO(7,0,0,60)==0,70);
        } else {
            CHECK(query(pipe[0],1,0) && query(pipe[1],4,4),71);
            long moved=DO(32,1,0,0);CHECK(moved>=3 && query(moved,4,4),72);
            long file=DO(2,"/work/data",0102,0600), null=DO(2,"/dev/null",2,0);
            CHECK(file>=3 && null>=3 && query(file,0x145,0x145) && query(null,0x145,0x145),73);
            struct pollfd mixed[3]={{pipe[0],1,99},{(int)moved,4,99},{(int)file,1,99}};
            CHECK(DO(7,mixed,3,0)==2 && mixed[0].revents==0 && mixed[1].revents==4 && mixed[2].revents==1,74);
            long writer=DO(32,pipe[1],0,0);CHECK(writer>=3 && DO(3,pipe[1],0,0)==0,75);
            CHECK(DO(1,writer,"X",1)==1 && query(pipe[0],1,1),76);
            CHECK(DO(3,writer,0,0)==0 && query(pipe[0],1,17),77);
            CHECK(DO(0,pipe[0],buffer,1)==1 && buffer[0]=='X' && query(pipe[0],1,16),78);
            CHECK(DO(3,pipe[0],0,0)==0 && DO(3,moved,0,0)==0 && DO(3,file,0,0)==0 && DO(3,null,0,0)==0,79);
        }
    } else if (mode=='t') {
        CHECK(DO(7,1,0,60)==0,11); // nfds=0 ignores the pointer and actually sleeps.
    } else if (mode=='k' || mode=='i') {
        struct pollfd entry={pipe[0],1,0};
        DO(7,&entry,1,mode=='k' ? 300000 : -1);
        return 12; // Runner terminates the genuinely parked caller.
    } else if (mode=='c') {
        struct pollfd entries[2]={{pipe[0],1,99},{0,1,99}};
        CHECK(DO(7,entries,2,2000)==1 && entries[0].revents==0 && (entries[1].revents&1),13);
        CHECK(DO(0,0,buffer,1)==1 && buffer[0]=='C',14);
    } else if (mode=='r' || mode=='w' || mode=='h' || mode=='d') {
        if (mode=='w') for (int i=0;i<16;++i) CHECK(DO(1,pipe[1],buffer,sizeof buffer)==sizeof buffer,15);
        long child=DO(57,0,0,0); CHECK(child>=0,16);
        if (child==0) {
            if (mode=='d') { for (;;) DO(39,0,0,0); }
            CHECK(DO(7,0,0,30)==0,17);
            if (mode=='r') CHECK(DO(1,pipe[1],"X",1)==1,18);
            if (mode=='w') CHECK(DO(0,pipe[0],buffer,sizeof buffer)==sizeof buffer,19);
            return 0; // Exit releases inherited pipe references and wakes HUP.
        }
        if (mode=='r' || mode=='h') CHECK(DO(3,pipe[1],0,0)==0,20);
        struct pollfd entry={mode=='w' ? pipe[1] : pipe[0],mode=='w' ? 4 : 1,99};
        if (mode=='d') {
            CHECK(DO(7,&entry,1,40)==0 && entry.revents==0,21);
            CHECK(DO(62,child,9,0)==0,22);
        } else {
            CHECK(DO(7,&entry,1,mode=='h' ? -2 : -1)==1,23); // Any negative timeout is infinite.
            if (mode=='r') CHECK((entry.revents&1) && DO(0,pipe[0],buffer,1)==1 && buffer[0]=='X',24);
            if (mode=='w') CHECK(entry.revents==4,25);
            if (mode=='h') CHECK(entry.revents==16 && DO(0,pipe[0],buffer,1)==0,26);
        }
        int status=-1;
        CHECK(DO(61,child,&status,0)==child && status==(mode=='d' ? 9 : 0),27);
    } else {
        CHECK(query(pipe[0],1,0) && query(pipe[1],4,4),30);
        CHECK(query(-1,0xffff,0) && query(123,0,32) && query(0x20000000,1,32),31);
        CHECK(DO(7,1,1,0)==-14 && DO(7,0,17,0)==-1 && DO(7,0,0,300001)==-1,32);
        CHECK(DO(7,&readonly_poll,1,0)==-14,33);
        long pages=call(9,0,8192,3,0x22,-1,0);
        CHECK(pages>0 && DO(10,pages+4096,4096,0)==0,34);
        CHECK(DO(7,pages+4092,1,0)==-14 && DO(11,pages,8192,0)==0,35);
        long moved=DO(32,1,0,0); CHECK(moved>=0 && query(moved,4,4),36);
        struct pollfd mixed[3]={{pipe[0],1,7},{(int)moved,4,7},{123,0,7}};
        CHECK(DO(7,mixed,3,0)==2 && mixed[0].revents==0 && mixed[1].revents==4 && mixed[2].revents==32,37);
        CHECK(DO(3,moved,0,0)==0,38);
        long file=DO(2,"/work/data",0102,0600), null=DO(2,"/dev/null",2,0), image=DO(2,"/bin/fixture",0,0);
        CHECK(file>=0 && null>=0 && image>=0,39);
        CHECK(query(file,0x145,0x145) && query(null,0x145,0x145),40);
        struct pollfd unsupported={(int)image,1,0};
        CHECK(DO(7,&unsupported,1,0)==-95,41); // Never poll the supervisor's same-numbered host FD.
        CHECK(DO(3,file,0,0)==0 && DO(3,null,0,0)==0 && DO(3,image,0,0)==0,42);
        for (int i=0;i<16;++i) CHECK(DO(1,pipe[1],buffer,sizeof buffer)==sizeof buffer,43);
        CHECK(query(pipe[1],4,0) && query(pipe[0],0x41,0x41),44);
        CHECK(DO(0,pipe[0],buffer,sizeof buffer)==sizeof buffer && query(pipe[1],0x104,0x104),45);
        long alias=DO(32,pipe[1],0,0); CHECK(alias>=0,46);
        CHECK(DO(3,pipe[1],0,0)==0 && query(pipe[0],1,1),47);
        CHECK(DO(3,alias,0,0)==0 && query(pipe[0],1,17) && query(pipe[0],0,16),48);
        for (int i=0;i<15;++i) CHECK(DO(0,pipe[0],buffer,sizeof buffer)==sizeof buffer,49);
        CHECK(query(pipe[0],1,16) && DO(0,pipe[0],buffer,1)==0,50);
        CHECK(DO(3,pipe[0],0,0)==0 && query(pipe[0],1,32),51);
        CHECK(DO(293,pipe,04000,0)==0 && DO(3,pipe[0],0,0)==0,52);
        CHECK(query(pipe[1],0,8) && query(pipe[1],4,12),53);
    }
    DO(1,1,"owned-poll: PASS\n",17);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall poll_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
