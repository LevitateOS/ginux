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
static const unsigned int readonly_status=0x12345678;
static volatile int fork_tid=0x1357;
static volatile int child_signal;
extern void signal_return(void);
static void child_handler(int signal, const int *info, void *context) {
    (void)context;
    child_signal=(signal==17 && info[4]==2 && info[5]==0 && info[6]==37 && DO(39,0,0,0)==1)?1:-1;
}
struct flock {short kind,whence;int padding;long start,len;int pid,padding2;};
struct clock_time { long seconds, nanos; };
static volatile int clock_signal;
static void clock_handler(int signal, const int *info, void *context) {
    (void)info;(void)context;
    struct clock_time t;
    if(signal==17 && DO(228,1,&t,0)==0) ++clock_signal;
}
static unsigned long clock_ns(struct clock_time t) {
    return (unsigned long)t.seconds*1000000000UL+t.nanos;
}
static long configured_clocks(void) {
    struct clock_time start, end, request={0,120000000}, remaining={-1,-1};
    CHECK(DO(228,0,&start,0)==0 && start.seconds>0,241);
    CHECK(DO(228,1,&start,0)==0 && DO(229,1,&end,0)==0,242);
    CHECK(DO(229,0,0,0)==0 && DO(228,1,0,0)==-14,243);
    long denied[]={2,3,4,5,6,7,-1,-5,-29};
    for(unsigned i=0;i<sizeof denied/sizeof denied[0];++i) {
        CHECK(DO(228,denied[i],&end,0)==-1 && DO(229,denied[i],0,0)==-1,244);
        CHECK(call(230,denied[i],0,(word)&request,0,0,0)==-1,245);
    }
    CHECK(DO(228,0x100000001UL,&end,0)==0,246);
    CHECK(DO(35,&request,&remaining,0)==0 && remaining.seconds==-1,247);
    CHECK(DO(228,1,&end,0)==0 && clock_ns(end)-clock_ns(start)>=120000000UL,248);
    for(word clock=0;clock<=1;++clock) {
        CHECK(call(230,clock,0,(word)&request,0,0,0)==0,249);
        CHECK(DO(228,clock,&end,0)==0,250);
        end.nanos+=120000000;if(end.nanos>=1000000000){++end.seconds;end.nanos-=1000000000;}
        CHECK(call(230,clock,1,(word)&end,1,0,0)==0,251);
        CHECK(DO(228,clock,&start,0)==0 && clock_ns(start)>=clock_ns(end),252);
    }
    request.seconds=0;request.nanos=0;
    CHECK(call(230,0,1,(word)&request,1,0,0)==0,253);
    request.seconds=-1;CHECK(DO(35,&request,0,0)==-22,254);
    request.seconds=0;request.nanos=1000000000;CHECK(DO(35,&request,0,0)==-22,255);
    request.seconds=301;request.nanos=0;CHECK(DO(35,&request,0,0)==-22,256);
    CHECK(DO(35,1,0,0)==-14 && call(230,1,2,(word)&request,0,0,0)==-22,257);
    word handler[4]={(word)clock_handler,0x14000004,(word)signal_return,0};
    CHECK(call(13,17,(word)handler,0,8,0,0)==0,258);
    for(int kind=0;kind<3;++kind) {
        long child=DO(57,0,0,0);CHECK(child>=0,259);
        if(child==0) {
            struct clock_time brief={0,150000000};
            if(DO(35,&brief,0,0)!=0) DO(60,38,0,0);
            DO(60,37,0,0);return 260;
        }
        request.seconds=2;request.nanos=0;remaining.seconds=-1;remaining.nanos=-1;
        if(kind==2) {CHECK(DO(228,0,&request,0)==0,265);request.seconds+=2;}
        long result=kind==0 ? DO(35,&request,&remaining,0) :
            call(230,kind==1?1:0,kind==2,(word)&request,(word)&remaining,0,0);
        CHECK(result==-4 && clock_signal==kind+1,261);
        if(kind==2) {CHECK(remaining.seconds==-1 && remaining.nanos==-1,266);}
        else {CHECK(remaining.seconds>=0 && clock_ns(remaining)>0 && clock_ns(remaining)<2000000000UL,262);}
        int status=-1;CHECK(DO(61,child,&status,0)==child && status==(37<<8),263);
    }
    CHECK(DO(1,1,"owned-tasks: PASS\n",18)==18,264);
    return 0;
}
static long lock_exec(void) {
    long fd=DO(2,"/work/exec-lock",0102,0600); CHECK(fd==3 && DO(32,fd,0,0)==4 && DO(72,4,2,1)==0,151);
    int ready[2], go[2]; CHECK(DO(22,ready,0,0)==0 && ready[1]==6 && DO(22,go,0,0)==0 && go[0]==7,152);
    long child=DO(57,0,0,0); CHECK(child>=0,153);
    if(!child) {
        struct flock lock={1,0,0,0,0,0,0};
        CHECK(DO(72,3,6,&lock)==0 && DO(73,3,6,0)==0 && DO(1,ready[1],"R",1)==1,154);
        CHECK(DO(0,go[0],buffer,1)==1,155);
        char *args[]={"/bin/fixture","CheckLocks",0}; char *environment[]={0};
        DO(59,args[0],args,environment); return 156;
    }
    CHECK(DO(0,ready[0],buffer,1)==1 && buffer[0]=='R',157);
    long independent=DO(2,"/work/exec-lock",2,0); CHECK(independent==9,158);
    struct flock lock={1,0,0,0,0,0,0};
    CHECK(DO(72,independent,5,&lock)==0 && lock.kind==1 && lock.pid==(int)child,159);
    CHECK(DO(3,3,0,0)==0 && DO(3,4,0,0)==0,160);
    lock.kind=1; CHECK(DO(72,independent,5,&lock)==0 && lock.kind==1,161);
    CHECK(DO(1,go[1],"G",1)==1 && DO(0,ready[0],buffer,1)==1 && buffer[0]=='E',162);
    lock.kind=1; CHECK(DO(72,independent,5,&lock)==0 && lock.kind==2,163);
    CHECK(DO(73,independent,6,0)==-11 && DO(1,go[1],"G",1)==1,164);
    int status=-1; CHECK(DO(61,child,&status,0)==child && status==0,165);
    CHECK(DO(73,independent,6,0)==0 && DO(3,independent,0,0)==0,166);
    for(int n=5;n<=8;++n) CHECK(DO(3,n,0,0)==0,167);
    return 0;
}
static long ordinary_resources(word argc, char **argv) {
    const word mib=1024*1024;
    long self=argc>3 ? 2 : 1;
    CHECK(argc>2 && DO(39,0,0,0)==self && DO(186,0,0,0)==self,200);
    word limits[2];
    CHECK(call(302,0,9,0,(word)limits,0,0)==0 && limits[0]==32*mib && limits[1]==limits[0],201);
    CHECK(call(9,0,64*mib,3,0x22,-1,0)==-12,202);
    long memory=call(9,0,mib,3,0x22,-1,0);CHECK(memory>0,203);
    ((volatile char *)memory)[0]=1;((volatile char *)memory)[mib-1]=2;
    CHECK(DO(11,memory,mib,0)==0,204);
    unsigned char expected[1024]={0},mask[1024]={0};
    const char *text=argv[2];
    while(*text) {
        word cpu=0;
        while(*text>='0' && *text<='9') cpu=cpu*10+(*text++-'0');
        CHECK(cpu<8192,205);expected[cpu/8]|=1<<(cpu%8);
        if(*text==',') ++text; else CHECK(*text==0,206);
    }
    for(word which=0;which<2;++which) {
        long size=DO(204,which ? self : 0,sizeof mask,mask);CHECK(size>0 && size<=1024,207);
        for(word i=0;i<sizeof mask;++i) CHECK(mask[i]==expected[i],208);
    }
    if(argc>3) return 0;
    long child=DO(57,0,0,0);CHECK(child>=0,209);
    if(child==0) {
        CHECK(call(302,0,9,0,(word)limits,0,0)==0 && limits[0]==32*mib && limits[1]==limits[0],210);
        long size=DO(204,2,sizeof mask,mask);CHECK(size>0 && size<=1024,211);
        for(word i=0;i<sizeof mask;++i) CHECK(mask[i]==expected[i],212);
        char *arguments[]={"/bin/fixture","Resources",argv[2],"exec",0};
        char *environment[]={0};
        DO(59,"/bin/fixture",arguments,environment);return 213;
    }
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,214);
    DO(1,1,"owned-tasks: PASS\n",18);
    return 0;
}
static long ordinary_umask(int after_exec) {
    static char metadata[144] __attribute__((aligned(8)));
    if(after_exec) { CHECK(DO(95,0,0,0)==0077,229);return 0; }
    CHECK(DO(95,0,0,0)==0022,220);
    long fd=DO(2,"/work/unmasked",0102,0666);CHECK(fd==3,221);
    CHECK(DO(5,fd,metadata,0)==0 && (*(unsigned int *)(metadata+24)&0777)==0666 && DO(3,fd,0,0)==0,222);
    CHECK(DO(83,"/work/unmasked-dir",0777,0)==0,223);
    CHECK(call(262,-100,(word)"/work/unmasked-dir",(word)metadata,0,0,0)==0 && (*(unsigned int *)(metadata+24)&0777)==0777,224);
    CHECK(DO(95,0027,0,0)==0,225);
    fd=call(257,-100,(word)"/work/masked",0102,0666,0,0);CHECK(fd==3,226);
    CHECK(DO(5,fd,metadata,0)==0 && (*(unsigned int *)(metadata+24)&0777)==0640 && DO(3,fd,0,0)==0,227);
    long child=DO(57,0,0,0);CHECK(child>=0,228);
    if(child==0) {
        CHECK(DO(95,0077,0,0)==0027,230);
        char *arguments[]={"/bin/fixture","UmaskExec",0}, *environment[]={0};
        DO(59,arguments[0],arguments,environment);return 231;
    }
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,232);
    CHECK(DO(95,0022,0,0)==0027,233);
    return 0;
}
long task_main(word *stack)
{
    word argc=*stack;
    char **argv=(char **)(stack+1);
    char mode=argc>1 ? argv[1][0] : 'f';
    if(mode=='W') {
        long usage[18]; int status=-1;
        for(int fault=0;fault<2;++fault) {
            long child=DO(57,0,0,0); CHECK(child>=0,270);
            if(child==0) { for(volatile word n=0;n<1000000;++n){} return 23; }
            for(int i=0;i<18;++i)usage[i]=-1;
            long result=call(61,child,(word)&status,0,fault?1:(word)usage,0,0);
            CHECK(result==(fault?-14:child) && status==(23<<8),271);
            if(!fault) CHECK(usage[0]>=0 && usage[1]>=0 && usage[2]>=0 && usage[3]>=0 && usage[4]>=0 && usage[17]>=0,272);
            CHECK(DO(61,child,&status,1)==-10,273);
        }
        DO(1,1,"owned-tasks: PASS\n",18);return 0;
    }
    if(mode=='Z') return configured_clocks();
    if(mode=='U') {
        long result=ordinary_umask(argc>1 && argv[1][5]=='E');if(result)return result;
        if(argv[1][5]!='E') { DO(1,1,"owned-tasks: PASS\n",18); }
        return 0;
    }
    if(mode=='C') {
        CHECK(DO(39,0,0,0)==2 && DO(72,3,1,0)==0 && DO(72,4,1,0)==-9,168);
        CHECK(DO(1,6,"E",1)==1 && DO(0,7,buffer,1)==1,169); return 0;
    }
    int ordinary_locks=mode=='O';
    if(ordinary_locks) mode='L';
    if(mode=='R') return ordinary_resources(argc,argv);
    CHECK(DO(39,0,0,0)==1 && DO(186,0,0,0)==1,10);
    CHECK(DO(110,0,0,0)==0 && DO(111,0,0,0)==1,11);
    word action[4]={1,0,0,0};
    CHECK(call(13,17,(word)action,0,8,0,0)==-95,81);
    action[0]=0; action[1]=2;
    CHECK(call(13,17,(word)action,0,8,0,0)==-95,82);
    if(mode=='E') {
        long status=lock_exec(); CHECK(status==0,status);
    } else if (mode=='L') {
        struct flock lock={1,0,0,10,20,0,0};
        long fd=DO(2,"/work/locked",0102,0600); CHECK(fd==3,123);
        CHECK(DO(86,"/work/locked","/work/alias",0)==0,124);
        long alias=DO(2,"/work/alias",0,0); CHECK(alias==4,125);
        CHECK(DO(72,fd,6,&lock)==0,126);
        lock.kind=2;lock.start=15;lock.len=5;CHECK(DO(72,fd,6,&lock)==0,127);
        int pipes[2];CHECK(DO(22,pipes,0,0)==0,128);
        long child=DO(57,0,0,0);CHECK(child>=0,129);
        if(child==0) {
            lock.kind=1;lock.start=10;lock.len=20;
            CHECK(DO(72,fd,5,&lock)==0 && lock.kind==1 && lock.pid==1 && lock.start==10 && lock.len==5,130);
            lock.kind=0;lock.start=30;lock.len=-20;CHECK(DO(72,fd,6,&lock)==-11,131);
            lock.kind=1;lock.start=15;lock.len=5;CHECK(DO(72,fd,5,&lock)==0 && lock.kind==2,132);
            lock.kind=1;CHECK(DO(72,fd,6,&lock)==0,133);
            CHECK(DO(1,pipes[1],"R",1)==1,134);
            lock.start=10;lock.len=20;CHECK(DO(72,fd,7,&lock)==0,135);
            CHECK(DO(72,fd,5,&lock)==0 && lock.kind==2,136);
            DO(60,37,0,0);__builtin_unreachable();
        }
        CHECK(DO(0,pipes[0],buffer,1)==1 && buffer[0]=='R',137);
        if(ordinary_locks) {
            CHECK(DO(1,1,"record-release-ready\n",21)==21 && DO(0,0,buffer,1)==1,170);
        }
        CHECK(DO(3,alias,0,0)==0,138); // Any alias close releases this process's inode locks.
        int status=-1;CHECK(DO(61,child,&status,0)==child && status==(37<<8),139);
        lock.kind=1;lock.start=0;lock.len=0;CHECK(DO(72,fd,6,&lock)==0,140);
        lock.kind=0;CHECK(DO(72,fd,5,&lock)==0 && lock.kind==2,141);
        if(!ordinary_locks) CHECK(DO(72,fd,6,1)==-14,142);
        CHECK(DO(73,fd,6,0)==0,142);
        child=DO(57,0,0,0);CHECK(child>=0,143);
        if(child==0) {
            CHECK(DO(73,fd,6,0)==0,144); // fork shares this open-description lock.
            long separate=DO(2,"/work/alias",0,0);CHECK(separate>=3,145);
            CHECK(DO(73,separate,6,0)==-11 && DO(1,pipes[1],"F",1)==1,146);
            CHECK(DO(73,separate,2,0)==0,147);
            DO(60,29,0,0);__builtin_unreachable();
        }
        CHECK(DO(0,pipes[0],buffer,1)==1 && buffer[0]=='F',148);
        if(ordinary_locks) {
            CHECK(DO(1,1,"flock-release-ready\n",20)==20 && DO(0,0,buffer,1)==1,171);
        }
        CHECK(DO(73,fd,8,0)==0 && DO(61,child,&status,0)==child && status==(29<<8),149);
        CHECK(DO(73,fd,6,0)==0 && DO(73,fd,16,0)==-22,150);
        if(ordinary_locks) {
            child=DO(57,0,0,0); CHECK(child>=0,172);
            if(!child) {
                CHECK(DO(1,pipes[1],"K",1)==1,173);
                lock.kind=1; lock.start=0; lock.len=0;
                DO(72,fd,7,&lock); return 174;
            }
            CHECK(DO(0,pipes[0],buffer,1)==1 && buffer[0]=='K',175);
            CHECK(DO(1,1,"cancel-ready\n",13)==13 && DO(0,0,buffer,1)==1,176);
            CHECK(DO(62,child,9,0)==0 && DO(61,child,&status,0)==child && status==9,177);
        }
        CHECK(DO(3,fd,0,0)==0,150);
    }
    else if (mode=='a') {
        long child=DO(57,0,0,0); CHECK(child>=0,117);
        if(child==0) {
            long grandchild=DO(57,0,0,0); CHECK(grandchild>=0,118);
            if(grandchild==0) {DO(60,37,0,0);__builtin_unreachable();}
            CHECK(grandchild==3 && DO(1,1,"zombie-ready\n",13)==13 && DO(0,0,buffer,1)==1,119);
            DO(60,19,0,0);__builtin_unreachable();
        }
        int status=-1;
        CHECK(child==2 && DO(61,child,&status,0)==child && status==(19<<8),120);
        CHECK(DO(61,3,&status,0)==3 && status==(37<<8),121);
        CHECK(DO(61,-1,&status,0)==-10,122);
    }
    else if (mode=='q') {
        for (word fault=0;fault<4;++fault) {
            long pages=-1;
            word destination=fault==0?(word)&readonly_status:1;
            if(fault>=2) {
                pages=call(9,0,8192,3,0x22,(word)-1,0);
                CHECK(pages>0,120);
                for(word i=4094;i<4098;++i) ((unsigned char *)pages)[i]=0x5a;
                destination=pages+4094;
                CHECK(DO(10,fault==2?pages+4096:pages,4096,fault==2?0:1)==0,121);
            }
            long child=DO(57,0,0,0);
            if(child==0) return 42;
            CHECK(child>1,122);
            CHECK(DO(61,child,destination,0)==-14,123);
            CHECK(DO(61,child,0,0)==-10,124);
            CHECK(readonly_status==0x12345678,125);
            if(fault==2) CHECK(((unsigned char *)pages)[4094]==0x5a && ((unsigned char *)pages)[4095]==0x5a,126);
            if(fault==3) for(word i=4094;i<4098;++i) CHECK(((unsigned char *)pages)[i]==0x5a,127);
            if(pages>0) CHECK(DO(11,pages,8192,0)==0,128);
        }
    } else
    if (mode=='f' || mode=='v' || mode=='c' || mode=='s') {
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
    } else if (mode=='l' || mode=='j' || mode=='p' || mode=='h' || mode=='x') {
        if(mode=='h') {
            word handler[4]={(word)child_handler,0x4000004,(word)signal_return,0};
            CHECK(call(13,17,(word)handler,0,8,0,0)==0,92);
        }
        long protected=call(9,0,mode=='x'?8192:4096,mode=='x'?3:1,0x22,(word)-1,0);
        CHECK(protected>0,90);
        if(mode=='x') {
            for(word i=4094;i<4098;++i) ((unsigned char *)protected)[i]=0x5a;
            CHECK(DO(10,protected+4096,4096,1)==0,130);
        }
        word address=mode=='j'?1:(mode=='p'?(word)protected:(mode=='x'?(word)protected+4094:(word)&fork_tid));
        long child=call(56,0x1200011,0,0,address,0,0);
        if (!child) {
            CHECK(DO(39,0,0,0)==2 && DO(186,0,0,0)==2,83);
            if(mode=='l' || mode=='h') { CHECK(fork_tid==2,84); }
            else { CHECK(fork_tid==0x1357 && *(volatile int *)protected==0,85); }
            if(mode=='x') for(word i=4094;i<4098;++i) CHECK(((unsigned char *)protected)[i]==0x5a,131);
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
        CHECK(DO(11,protected,mode=='x'?8192:4096,0)==0,91);
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
        CHECK(DO(61,child,1,0)==-14,35); // Linux still reaps the child on a copy fault.
        CHECK(DO(61,child,&status,0)==-10 && status==123,36);
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
    } else if (mode=='b' || mode=='B') {
        int pipe[2];
        CHECK(DO(22,pipe,0,0)==0,60);
        long children[31];
        for (word i=0;i<31;++i) {
            long child=DO(57,0,0,0);
            if (child==0) { CHECK(DO(0,pipe[0],buffer,1)==1,61); return 0; }
            CHECK(child>1,62);
            children[i]=child;
        }
        CHECK(DO(57,0,0,0)==-11,63);
        if (mode=='b') {
            CHECK(DO(56,17|0x800000,0,0)==-38,64); // CLONE_UNTRACED
            CHECK(DO(56,17|0x20000000,0,0)==-38,65); // CLONE_NEWPID
            CHECK(DO(56,17|0x400,0,0)==-38,66); // CLONE_FILES
        }
        for (word i=0;i<31;++i) CHECK(DO(62,children[i],9,0)==0,67);
        for (word i=0;i<31;++i) { int status; CHECK(DO(61,children[i],&status,0)==children[i] && status==9,68); }
        long child=DO(57,0,0,0);
        if (child==0) return 19;
        int status;
        CHECK(child>32 && DO(61,child,&status,0)==child && status==(19<<8),69);
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
