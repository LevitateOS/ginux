/* Real configured-launch anonymous pipe and local socket pair checks. No native
   pipe or socket descriptors. */
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
static const char immutable[] = "read-only guest buffer";
static char buffer[65536];
static char data[65536];
static char meta[256] __attribute__((aligned(8)));
static int named(const char *a,const char *b){while(*a && *a==*b){++a;++b;}return *a==*b;}
static long ordinary_fionbio(void){
    int pair[2],value=0; CHECK(DO(293,pair,02004000,0)==0,150);
    CHECK(call(262,pair[0],(word)"",(word)meta,0x1100,0,0)==0,163);
    CHECK(call(332,pair[0],(word)"",0x5000,0x7ff,(word)meta,0)==0,164);
    long alias=DO(32,pair[1],0,0); CHECK(alias>=3,151);
    CHECK(DO(72,alias,4,06001)==0 && DO(16,alias,0x5421,&value)==0,152);
    CHECK(DO(72,pair[1],3,0)==02001 && DO(72,pair[1],1,0)==1 && DO(72,alias,1,0)==0,153);
    value=-7;CHECK(DO(16,pair[1],0x5421,&value)==0 && DO(72,alias,3,0)==06001,154);
    value=0;CHECK(DO(16,pair[0],0x5421,&value)==0 && DO(72,pair[0],3,0)==0,155);
    long child=DO(57,0,0,0);CHECK(child>=0,156);
    if(child==0){DO(60,DO(1,alias,"F",1)==1?0:157,0,0);__builtin_unreachable();}
    CHECK(DO(0,pair[0],buffer,1)==1 && buffer[0]=='F',158);
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,159);
    value=1;CHECK(DO(16,pair[0],0x5421,&value)==0 && DO(0,pair[0],buffer,1)==-11,160);
    CHECK(DO(3,alias,0,0)==0 && DO(3,pair[1],0,0)==0 && DO(0,pair[0],buffer,1)==0,161);
    CHECK(DO(3,pair[0],0,0)==0,162);return 0;
}
static long ordinary_streams(void){
    int pipes[12][2];struct {int fd;short events,revents;} polls[12];
    for(int i=0;i<12;++i){CHECK(DO(293,pipes[i],04000,0)==0,170);polls[i].fd=pipes[i][0];polls[i].events=1;polls[i].revents=0;CHECK(DO(1,pipes[i][1],"S",1)==1,171);}
    CHECK(DO(7,polls,12,0)==12,172);
    for(int i=0;i<12;++i)CHECK((polls[i].revents&1) && DO(0,pipes[i][0],buffer,1)==1 && buffer[0]=='S',173);
    long child=DO(57,0,0,0);CHECK(child>=0,174);
    if(child==0){long grandchild=DO(57,0,0,0);CHECK(grandchild>=0,175);if(grandchild==0){DO(60,DO(1,pipes[11][1],"G",1)==1?0:176,0,0);__builtin_unreachable();}int status=-1;CHECK(DO(61,grandchild,&status,0)==grandchild && status==0,177);DO(60,DO(1,pipes[10][1],"N",1)==1?0:178,0,0);__builtin_unreachable();}
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,179);
    CHECK(DO(0,pipes[11][0],buffer,1)==1 && buffer[0]=='G' && DO(0,pipes[10][0],buffer,1)==1 && buffer[0]=='N',180);
    for(int i=0;i<12;++i)CHECK(DO(3,pipes[i][1],0,0)==0 && DO(0,pipes[i][0],buffer,1)==0 && DO(3,pipes[i][0],0,0)==0,181);
    return 0;
}
static long ordinary_vectors(void) {
    int pair[2];word vectors[32]={0};
    CHECK(DO(293,pair,04000,0)==0,90);
    CHECK(DO(19,pair[0],vectors,0)==0 && DO(20,pair[1],vectors,0)==0,91);
    vectors[0]=(word)"ab";vectors[1]=2;vectors[4]=(word)"cde";vectors[5]=3;
    CHECK(DO(20,pair[1],vectors,3)==5,92);
    vectors[0]=(word)buffer;vectors[1]=1;vectors[4]=(word)(buffer+1);vectors[5]=8;
    CHECK(DO(19,pair[0],vectors,3)==5 && buffer[0]=='a' && buffer[4]=='e',93);
    for(word i=0;i<16;++i) { data[i]=(char)('A'+i);vectors[2*i]=(word)(data+i);vectors[2*i+1]=1; }
    CHECK(DO(20,pair[1],vectors,16)==16 && DO(20,pair[1],vectors,17)==-22,94);
    for(word i=0;i<16;++i) vectors[2*i]=(word)(buffer+i);
    CHECK(DO(19,pair[0],vectors,16)==16,95);
    for(word i=0;i<16;++i) CHECK(buffer[i]==data[i],96);
    for(word i=0;i<65536;++i) data[i]=(char)(i%251);
    for(word i=0;i<65536-4096;i+=4096) CHECK(DO(1,pair[1],data+i,4096)==4096,97);
    CHECK(DO(1,pair[1],data,4095)==4095,98);
    vectors[0]=(word)"x";vectors[1]=1;vectors[2]=(word)"y";vectors[3]=1;
    CHECK(DO(20,pair[1],vectors,2)==-11 && DO(0,pair[0],buffer,1)==1,99);
    CHECK(DO(20,pair[1],vectors,2)==2,100);
    for(word i=0;i<65536;i+=4096) CHECK(DO(0,pair[0],buffer,4096)==4096,101);
    vectors[0]=(word)data;vectors[1]=4090;vectors[2]=(word)(data+4090);vectors[3]=4102;
    CHECK(DO(20,pair[1],vectors,2)==4096,102);
    vectors[0]=(word)buffer;vectors[1]=4090;vectors[2]=(word)(buffer+4090);vectors[3]=4102;
    CHECK(DO(19,pair[0],vectors,2)==4096,103);
    for(word i=0;i<4096;++i) CHECK(buffer[i]==data[i],104);
    CHECK(DO(0,pair[0],buffer,1)==-11,105);
    long alias=DO(32,pair[1],0,0);CHECK(alias>=3 && DO(3,pair[1],0,0)==0,106);
    vectors[0]=(word)"bye";vectors[1]=3;
    CHECK(DO(20,alias,vectors,1)==3 && DO(3,alias,0,0)==0,107);
    vectors[0]=(word)buffer;vectors[1]=16;
    CHECK(DO(19,pair[0],vectors,1)==3 && buffer[0]=='b' && buffer[2]=='e',108);
    CHECK(DO(19,pair[0],vectors,1)==0 && DO(3,pair[0],0,0)==0,109);
    DO(1,1,"owned-pipes: PASS\n",18);
    return 0;
}
static long ordinary_blocking_large(void) {
    static char large[196733];
    for(word i=0;i<sizeof(large);++i) large[i]=(char)(i%251);
    for(int vector=0;vector<2;++vector) {
        int pair[2];CHECK(DO(22,pair,0,0)==0,190);
        long child=DO(57,0,0,0);CHECK(child>=0,191);
        if(child==0) {
            CHECK(DO(3,pair[0],0,0)==0,192);
            word iov[6]={(word)large,3000,(word)(large+3000),100000,
                         (word)(large+103000),sizeof(large)-103000};
            long n=vector?DO(20,pair[1],iov,3):DO(1,pair[1],large,sizeof(large));
            DO(60,n==(long)sizeof(large)?0:193,0,0);__builtin_unreachable();
        }
        CHECK(DO(3,pair[1],0,0)==0,194);
        word received=0;
        for(;;) {
            long n=DO(0,pair[0],buffer,sizeof(buffer));CHECK(n>=0,195);
            if(n==0)break;
            CHECK(received+(word)n<=sizeof(large),196);
            for(long i=0;i<n;++i)CHECK(buffer[i]==large[received+(word)i],197);
            received+=(word)n;
        }
        int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,198);
        CHECK(received==sizeof(large) && DO(3,pair[0],0,0)==0,199);
    }
    return 0;
}
/* Local socket pairs: SOCK_STREAM byte streams, both directions. */
struct __attribute__((packed)) epoll_event_x86 { unsigned events; unsigned long data; };
static long socket_stream(void){
    int sv[2],value=0,size=sizeof value;struct {int fd;short events,revents;} polled[2];
    unsigned short family[4]={0};word vectors[4];
    CHECK(call(53,1,1,0,(word)sv,0,0)==0 && sv[0]==3 && sv[1]==4,200);
    CHECK(DO(72,sv[0],1,0)==0 && DO(72,sv[0],3,0)==2,201);
    CHECK(DO(5,sv[0],meta,0)==0 && (*(unsigned int *)(meta+24)&0170000)==0140000,202);
    CHECK((*(unsigned int *)(meta+24)&0777)==0777 && DO(8,sv[0],0,0)==-29,203);
    CHECK(call(262,sv[1],(word)"",(word)meta,0x1000,0,0)==0 && (*(unsigned int *)(meta+24)&0170000)==0140000,204);
    // Status flags: FIONBIO and F_SETFL share the open socket's O_NONBLOCK.
    value=1;CHECK(DO(16,sv[0],0x5421,&value)==0 && DO(72,sv[0],3,0)==04002,205);
    CHECK(DO(72,sv[0],4,0)==0 && DO(72,sv[0],3,0)==2,206);
    CHECK(DO(72,sv[0],4,04000)==0 && DO(72,sv[1],4,04000)==0,207);
    CHECK(DO(0,sv[0],buffer,8)==-11 && DO(0,sv[1],buffer,8)==-11,208);
    CHECK(DO(72,sv[0],1032,0)==-9 && DO(16,sv[0],0x5401,meta)==-25,209);
    // Identity without names or credentials.
    CHECK(call(55,sv[0],1,3,(word)&value,(word)&size,0)==0 && value==1 && size==4,210);
    size=4;CHECK(call(55,sv[1],1,39,(word)&value,(word)&size,0)==0 && value==1,211);
    size=4;CHECK(call(55,sv[1],1,4,(word)&value,(word)&size,0)==0 && value==0,212);
    size=4;CHECK(call(55,sv[1],1,17,(word)meta,(word)&size,0)==-92,213);
    value=65536;CHECK(call(54,sv[0],1,7,(word)&value,4,0)==0 && call(54,sv[0],1,8,(word)&value,4,0)==0,214);
    CHECK(call(54,sv[0],1,7,(word)&value,2,0)==-22 && call(54,sv[0],1,16,(word)&value,4,0)==-92,215);
    size=sizeof family;CHECK(call(51,sv[0],(word)family,(word)&size,0,0,0)==0 && family[0]==1 && size==2,216);
    size=sizeof family;CHECK(call(52,sv[1],(word)family,(word)&size,0,0,0)==0 && family[0]==1 && size==2,217);
    CHECK(call(42,sv[0],(word)family,2,0,0,0)==-106,218);
    // Both directions carry bytes; reads ignore write boundaries.
    CHECK(DO(1,sv[0],"hello",5)==5 && DO(1,sv[1],"world!",6)==6,219);
    CHECK(DO(16,sv[1],0x541b,&value)==0 && value==5 && DO(16,sv[0],0x541b,&value)==0 && value==6,220);
    polled[0].fd=sv[0];polled[0].events=5;polled[0].revents=0;polled[1].fd=sv[1];polled[1].events=1;polled[1].revents=0;
    CHECK(DO(7,polled,2,0)==2 && polled[0].revents==5 && polled[1].revents==1,221);
    CHECK(DO(0,sv[1],buffer,3)==3 && buffer[0]=='h' && buffer[2]=='l',222);
    CHECK(DO(1,sv[0],"ab",2)==2 && DO(0,sv[1],buffer,16)==4 && buffer[0]=='l' && buffer[1]=='o' && buffer[3]=='b',223);
    CHECK(DO(0,sv[0],buffer,16)==6 && buffer[5]=='!',224);
    CHECK(call(44,sv[0],(word)"xy",2,0x4000,0,0)==2 && call(45,sv[1],(word)buffer,8,0x40,0,0)==2 && buffer[1]=='y',225);
    CHECK(call(44,sv[0],(word)"xy",2,0,(word)family,2)==-95 && call(45,sv[1],(word)buffer,8,2,0,0)==-95,226);
    vectors[0]=(word)"vec";vectors[1]=3;vectors[2]=(word)"tor";vectors[3]=3;
    CHECK(DO(20,sv[1],vectors,2)==6,227);
    vectors[0]=(word)buffer;vectors[1]=2;vectors[2]=(word)(buffer+2);vectors[3]=8;
    CHECK(DO(19,sv[0],vectors,2)==6 && buffer[0]=='v' && buffer[5]=='r',228);
    CHECK(DO(1,sv[0],buffer,0)==0 && DO(0,sv[1],buffer,0)==0,229);
    // Bounded: a full direction is EAGAIN and not writable until drained.
    for(word i=0;i<sizeof data;++i) data[i]=(char)(i%251);
    word filled=0;
    for(;;){long n=DO(1,sv[1],data+filled%4096,4096);if(n==-11)break;CHECK(n==4096,230);filled+=4096;}
    CHECK(filled==65536 && DO(1,sv[1],data,1)==-11,231);
    polled[0].fd=sv[1];polled[0].events=4;polled[0].revents=0;
    CHECK(DO(7,polled,1,0)==0,232);
    CHECK(DO(16,sv[0],0x541b,&value)==0 && value==65536,233);
    CHECK(DO(0,sv[0],buffer,4096)==4096 && buffer[1]==data[1],234);
    polled[0].revents=0;CHECK(DO(7,polled,1,0)==1 && polled[0].revents==4,235);
    while(DO(0,sv[0],buffer,4096)>0){}
    // shutdown(SHUT_WR): the peer drains then reads EOF with RDHUP but no HUP;
    // the reverse direction keeps working and the shut side gets EPIPE.
    CHECK(DO(1,sv[0],"tail",4)==4 && DO(48,sv[0],1,0)==0 && DO(48,sv[0],3,0)==-22,236);
    polled[0].fd=sv[1];polled[0].events=0x2001;polled[0].revents=0;
    CHECK(DO(7,polled,1,0)==1 && polled[0].revents==0x2001,237);
    CHECK(DO(0,sv[1],buffer,8)==4 && buffer[0]=='t' && DO(0,sv[1],buffer,8)==0,238);
    CHECK(call(44,sv[0],(word)"x",1,0x4000,0,0)==-32 && call(44,sv[0],(word)"",0,0x4000,0,0)==-32,239);
    CHECK(DO(1,sv[1],"back",4)==4 && DO(0,sv[0],buffer,8)==4 && buffer[0]=='b',240);
    // Closing the peer everywhere: EOF after buffered bytes, HUP, EPIPE.
    long alias=DO(32,sv[1],0,0);CHECK(alias==5,241);
    CHECK(DO(1,alias,"last",4)==4 && DO(3,sv[1],0,0)==0 && DO(0,sv[0],buffer,1)==1,242);
    CHECK(DO(3,alias,0,0)==0,243);
    polled[0].fd=sv[0];polled[0].events=1;polled[0].revents=0;
    CHECK(DO(7,polled,1,0)==1 && polled[0].revents==17,244);
    CHECK(DO(0,sv[0],buffer,8)==3 && buffer[0]=='a' && DO(0,sv[0],buffer,8)==0,245);
    CHECK(call(44,sv[0],(word)"x",1,0x4000,0,0)==-32,246);
    CHECK(DO(3,sv[0],0,0)==0,247);
    // A blocking stream write larger than the buffer completes through a
    // forked peer; the reader sees every byte then EOF.
    static char large[196733];
    for(word i=0;i<sizeof(large);++i) large[i]=(char)(i%253);
    CHECK(call(53,1,1|02000000,0,(word)sv,0,0)==0 && DO(72,sv[0],1,0)==1,248);
    long child=DO(57,0,0,0);CHECK(child>=0,249);
    if(child==0){
        CHECK(DO(3,sv[0],0,0)==0,250);
        long n=DO(1,sv[1],large,sizeof(large));
        DO(60,n==(long)sizeof(large) && DO(0,sv[1],buffer,8)==2 && buffer[0]=='o'?0:251,0,0);__builtin_unreachable();
    }
    CHECK(DO(3,sv[1],0,0)==0,252);
    word received=0;
    while(received<sizeof(large)){
        long n=DO(0,sv[0],buffer,sizeof(buffer));CHECK(n>0,253);
        for(long i=0;i<n;++i)CHECK(buffer[i]==large[received+(word)i],254);
        received+=(word)n;
    }
    CHECK(DO(1,sv[0],"ok",2)==2,255);
    int status=-1;CHECK(DO(61,child,&status,0)==child && status==0,256);
    CHECK(DO(0,sv[0],buffer,8)==0 && DO(3,sv[0],0,0)==0,257);
    // Sequenced packets keep boundaries; FIONREAD sums queued payloads.
    CHECK(call(53,1,5,0,(word)sv,0,0)==0,258);
    CHECK(DO(1,sv[0],"abc",3)==3 && DO(1,sv[0],"de",2)==2,259);
    CHECK(DO(16,sv[1],0x541b,&value)==0 && value==5,260);
    size=4;CHECK(call(55,sv[1],1,3,(word)&value,(word)&size,0)==0 && value==5,261);
    CHECK(DO(48,sv[0],1,0)==0 && DO(0,sv[1],buffer,8)==3 && DO(0,sv[1],buffer,8)==2 && DO(0,sv[1],buffer,8)==0,262);
    CHECK(DO(3,sv[0],0,0)==0 && DO(3,sv[1],0,0)==0,263);
    // Pipes, FIFOs and counters are not sockets.
    int pair[2];CHECK(DO(293,pair,0,0)==0,264);
    CHECK(DO(48,pair[0],1,0)==-88 && call(55,pair[0],1,3,(word)&value,(word)&size,0)==-88,265);
    CHECK(DO(3,pair[0],0,0)==0 && DO(3,pair[1],0,0)==0,266);
    // Released pairs return their buffers to the bounded pool.
    for(int i=0;i<40;++i){CHECK(call(53,1,1,0,(word)sv,0,0)==0,267);CHECK(DO(3,sv[0],0,0)==0 && DO(3,sv[1],0,0)==0,268);}
    return 0;
}
/* What libuv's uv_spawn does for a captured stdout: a CLOEXEC stream pair,
   buffer-size hints, a CLOEXEC error pipe, fork, dup2 onto stdout, blocking
   stdout in the child, exec; the parent switches its end to FIONBIO and
   epoll-reads until EOF, then waits. */
static long socket_spawn(void){
    int sv[2],errors[2],value,status=-1;
    long epfd=DO(291,02000000,0,0);CHECK(epfd>=0,300);
    CHECK(call(53,1,1|02000000,0,(word)sv,0,0)==0,301);
    value=65536;
    for(int i=0;i<2;++i)CHECK(call(54,sv[i],1,8,(word)&value,4,0)==0 && call(54,sv[i],1,7,(word)&value,4,0)==0,302);
    CHECK(DO(293,errors,02000000,0)==0,303);
    long child=DO(57,0,0,0);CHECK(child>=0,304);
    if(child==0){
        static const char *const argv[]={"/bin/echo","hello","from","socketpair",0};
        static const char *const envp[]={0};
        long fd=DO(33,sv[1],1,0);
        if(fd==1){long flags=DO(72,1,3,0);if(flags>=0)DO(72,1,4,flags&~04000);}
        int error=-(int)DO(59,argv[0],argv,envp);
        DO(1,errors[1],&error,sizeof error);
        DO(60,127,0,0);__builtin_unreachable();
    }
    CHECK(DO(3,sv[1],0,0)==0 && DO(3,errors[1],0,0)==0,305);
    value=1;CHECK(DO(16,sv[0],0x5421,&value)==0,306);
    CHECK(DO(0,errors[0],&value,sizeof value)==0 && DO(3,errors[0],0,0)==0,307);
    struct epoll_event_x86 event={1,0x1234567890abcdefUL},ready[4];
    CHECK(call(233,epfd,1,sv[0],(word)&event,0,0)==0,308);
    word received=0;
    for(;;){
        long n=call(232,epfd,(word)ready,4,-1,0,0);CHECK(n==1 && ready[0].data==0x1234567890abcdefUL,309);
        int eof=0;
        for(;;){
            long got=DO(0,sv[0],buffer+received,sizeof(buffer)-received);
            if(got==-11)break;
            CHECK(got>=0,310);
            if(got==0){eof=1;break;}
            received+=(word)got;
        }
        if(eof)break;
    }
    CHECK(DO(61,child,&status,0)==child && status==0,311);
    static const char expected[]="hello from socketpair\n";
    CHECK(received==sizeof(expected)-1,312);
    for(word i=0;i<received;++i)CHECK(buffer[i]==expected[i],313);
    CHECK(call(233,epfd,2,sv[0],0,0,0)==0 && DO(3,sv[0],0,0)==0 && DO(3,epfd,0,0)==0,314);
    return 0;
}
/* A static echo stand-in for exec targets in this fixture's root. */
static long echo(word argc,char **argv){
    word length=0;
    for(word i=1;i<argc;++i){
        for(const char *c=argv[i];*c && length<sizeof(buffer)-2;++c)buffer[length++]=*c;
        if(i+1<argc)buffer[length++]=' ';
    }
    buffer[length++]='\n';
    return DO(1,1,buffer,length)==(long)length?0:1;
}
long pipe_main(word *stack)
{
    word argc = *stack;
    char **argv = (char **)(stack + 1);
    int pair[2];
    const char *self=argv[0];while(*self)++self;
    if(self-argv[0]>=4 && named(self-4,"echo")) return echo(argc,argv);
    if(argc>1 && (named(argv[1],"socket-stream") || named(argv[1],"socket-spawn"))) {
        long result=named(argv[1],"socket-stream")?socket_stream():socket_spawn();
        if(result)return result;
        DO(1,1,"owned-pipes: PASS\n",18);return 0;
    }
    if(argc>1 && named(argv[1],"socket-sigpipe")) {
        CHECK(call(53,1,1,0,(word)pair,0,0)==0 && DO(3,pair[1],0,0)==0,320);
        DO(1,pair[0],data,1);
        return 321; // Default SIGPIPE must terminate the caller.
    }
    if(argc>1 && named(argv[1],"ordinary-blocking-large")) {
        long result=ordinary_blocking_large();if(result)return result;
        DO(1,1,"owned-pipes: PASS\n",18);return 0;
    }
    if(argc>1 && (named(argv[1],"ordinary-fionbio") || named(argv[1],"ordinary-streams"))){
        long result=named(argv[1],"ordinary-fionbio")?ordinary_fionbio():ordinary_streams();
        if(result)return result;
        DO(1,1,"owned-pipes: PASS\n",18);return 0;
    }
    if (argc > 1 && (argv[1][0] == 'p' || named(argv[1],"ordinary-packet"))) {
        int full=argv[1][0]=='p';
        if(full){
        CHECK(call(53,2,5,0,(word)pair,0,0)==-95,100);
        CHECK(call(53,1,2,0,(word)pair,0,0)==-95,101);
        CHECK(call(53,1,5,0,1,0,0)==-14,102);
        }
        CHECK(call(53,1,5|02004000,0,(word)pair,0,0)==0,103);
        CHECK(pair[0]==3 && pair[1]==4,104);
        CHECK(DO(72,pair[0],1,0)==1 && DO(72,pair[0],3,0)==04002,105);
        CHECK(call(45,pair[0],(word)buffer,8,0,0,0)==-11,106);
        CHECK(DO(1,pair[0],"abcdef",6)==6 && DO(1,pair[0],"xy",2)==2,107);
        struct {int fd;short events,revents;} polled={pair[1],1,0};
        CHECK(DO(7,&polled,1,0)==1 && (polled.revents&1),130);
        CHECK(call(45,pair[1],(word)buffer,2,0,0,0)==2 && buffer[0]=='a' && buffer[1]=='b',108);
        CHECK(DO(0,pair[1],buffer,8)==2 && buffer[0]=='x' && buffer[1]=='y',109);
        CHECK(call(44,pair[1],(word)"reply",5,0,0,0)==5,110);
        CHECK(DO(0,pair[0],buffer,8)==5 && buffer[0]=='r',111);
        if(full){
        CHECK(DO(1,pair[0],data,4097)==-90,112);
        CHECK(DO(1,pair[0],1,8)==-14 && DO(0,pair[1],buffer,8)==-11,113);
        }
        CHECK(DO(5,pair[0],meta,0)==0 && (*(unsigned int *)(meta+24)&0170000)==0140000,114);
        long alias=DO(32,pair[1],0,0);
        CHECK(alias>=3 && DO(3,pair[1],0,0)==0,115);
        CHECK(DO(1,pair[0],"last",4)==4 && DO(3,pair[0],0,0)==0,116);
        polled.fd=(int)alias;polled.revents=0;
        CHECK(DO(7,&polled,1,0)==1 && (polled.revents&17)==17,131);
        CHECK(DO(0,alias,buffer,8)==4 && buffer[0]=='l' && DO(0,alias,buffer,8)==0,117);
        if(full){CHECK(call(44,alias,(word)"x",1,0x4000,0,0)==-32,118);}
        CHECK(DO(3,alias,0,0)==0,119);
        // Closed pairs release both directions and their capacity.
        for (int i=0;i<20;i++) {
            CHECK(call(53,1,5,0,(word)pair,0,0)==0,120);
            CHECK(DO(3,pair[0],0,0)==0 && DO(3,pair[1],0,0)==0,121);
        }
        CHECK(call(53,1,5,0,(word)pair,0,0)==0,122);
        CHECK(DO(1,pair[0],buffer,0)==0 && DO(0,pair[1],buffer,8)==0,123);
        long child=DO(57,0,0,0); CHECK(child>=0,124);
        if(child==0){CHECK(DO(3,pair[0],0,0)==0 && DO(1,pair[1],"child",5)==5,125);return DO(0,pair[1],buffer,1)==1 && buffer[0]=='P'?0:126;}
        CHECK(DO(3,pair[1],0,0)==0 && DO(0,pair[0],buffer,8)==5 && buffer[0]=='c' && buffer[4]=='d',127);
        CHECK(DO(1,pair[0],"P",1)==1,128);int status=-1;
        CHECK(DO(61,child,&status,0)==child && status==0 && DO(0,pair[0],buffer,8)==0 && DO(3,pair[0],0,0)==0,129);
        DO(1,1,"owned-pipes: PASS\n",18);
        return 0;
    }
    if (argc>1 && argv[1][0]=='v') return ordinary_vectors();
    if (argc > 1 && argv[1][0] == 'b') {
        CHECK(DO(293,pair,0,0) == 0, 10);
        return DO(0,pair[0],buffer,1) == -11 ? 11 : 12;
    }
    if (argc > 1 && argv[1][0] == 'w') {
        CHECK(DO(22,pair,0,0) == 0, 13);
        for (word i=0;i<65536;i+=4096) CHECK(DO(1,pair[1],data,4096) == 4096, 14);
        return DO(1,pair[1],data,1) == -11 ? 15 : 16;
    }
    if (argc > 1 && argv[1][0] == 's') {
        CHECK(DO(293,pair,0,0) == 0, 17);
        CHECK(DO(3,pair[0],0,0) == 0, 18);
        DO(1,pair[1],data,1);
        return 19; // Default SIGPIPE must terminate the caller.
    }
    CHECK(DO(293,pair,1UL<<32,0) == -22, 20);
    CHECK(DO(293,pair,040000,0) == -22, 21);
    CHECK(DO(293,1,0,0) == -14, 22);
    CHECK(DO(293,immutable,0,0) == -14, 23);
    long pages=call(9,0,8192,3,0x22,-1,0);
    CHECK(pages>0 && DO(10,pages+4096,4096,0) == 0, 24);
    CHECK(DO(293,pages+4092,0,0) == -14, 25);
    CHECK(DO(293,pair,02004000,0) == 0, 26);
    CHECK(pair[0] == 3 && pair[1] == 4, 27);
    CHECK(DO(0,pair[0],buffer,1) == -11, 28);
    CHECK(DO(1,pair[0],data,1) == -9 && DO(0,pair[1],buffer,1) == -9, 29);
    CHECK(DO(72,pair[0],1,0) == 1 && DO(72,pair[1],1032,0) == 65536, 30);
    CHECK(DO(5,pair[0],meta,0) == 0, 31);
    CHECK((*(unsigned int *)(meta+24) & 0170000) == 0010000, 32);
    word inode=*(word *)(meta+8);
    CHECK(call(332,pair[1],(word)"",0x1000,0x7ff,(word)meta,0) == 0, 33);
    CHECK(*(word *)(meta+32) == inode, 34);
    CHECK(call(262,pair[0],(word)"",(word)meta,0x1100,0,0)==0,163);
    CHECK(call(332,pair[0],(word)"",0x5000,0x7ff,(word)meta,0)==0,164);
    CHECK(DO(8,pair[0],0,0) == -29, 35);
    CHECK(DO(1,pair[1],1,5) == -14, 36);
    CHECK(DO(0,pair[0],buffer,1) == -11, 37);
    CHECK(DO(1,pair[1],"hello",5) == 5, 38);
    CHECK(DO(0,pair[0],immutable,5) == -14, 39);
    CHECK(DO(0,pair[0],pages+4094,5) == 2, 40);
    CHECK(DO(0,pair[0],buffer,5) == 3 && buffer[0] == 'l' && buffer[2] == 'o', 41);
    CHECK(DO(1,pair[1],pages+4094,5) == -14, 42);
    CHECK(DO(0,pair[0],buffer,1) == -11, 43);
    CHECK(DO(16,pair[0],0x5421,1) == -14, 84);
    CHECK(DO(16,pair[0],0x5421,pages+4094) == -14, 85);
    CHECK(DO(72,pair[0],3,0) == 04000, 86); // Failed copyin cannot change flags.
    CHECK(DO(16,pair[0],0x5422,buffer) == -25, 87);
    CHECK(DO(11,pages,8192,0) == 0, 44);
    for (word i=0;i<sizeof data;++i) data[i]=i%251;
    for (word i=0;i<61440;i+=4096) CHECK(DO(1,pair[1],data+i,4096) == 4096, 45);
    CHECK(DO(1,pair[1],data+61440,4095) == 4095, 46);
    CHECK(DO(1,pair[1],"xx",2) == -11, 47); // Atomic write cannot consume the final byte.
    CHECK(DO(1,pair[1],data+65535,1) == 1, 48);
    CHECK(DO(1,pair[1],data,1) == -11, 49);
    for (word i=0;i<65536;i+=4096) CHECK(DO(0,pair[0],buffer+i,4096) == 4096, 50);
    for (word i=0;i<65536;++i) CHECK(buffer[i] == data[i], 51);
    long alias=DO(32,pair[1],0,0);
    CHECK(alias == 5, 52);
    CHECK(DO(72,alias,1,0) == 0, 53);
    CHECK(DO(72,alias,4,1) == 0 && DO(72,pair[1],3,0) == 1, 54);
    CHECK(DO(72,pair[1],4,04001) == 0 && DO(72,alias,3,0) == 04001, 55);
    int nonblock = 0;
    CHECK(DO(72,alias,4,06001) == 0, 88);
    CHECK(DO(16,alias,0x5421,&nonblock) == 0, 89);
    CHECK(DO(72,pair[1],3,0) == 02001, 90); // Preserve APPEND and access mode.
    nonblock = -7; // Any nonzero int enables O_NONBLOCK.
    CHECK(DO(16,pair[1],0x5421,&nonblock) == 0, 91);
    CHECK(DO(72,alias,3,0) == 06001 && DO(72,pair[1],1,0) == 1, 92);
    CHECK(DO(3,pair[1],0,0) == 0, 56);
    CHECK(DO(0,pair[0],buffer,1) == -11, 57);
    CHECK(DO(1,alias,"bye",3) == 3, 58);
    CHECK(DO(3,alias,0,0) == 0, 59);
    CHECK(DO(0,pair[0],buffer,5) == 3 && buffer[0] == 'b', 60);
    CHECK(DO(0,pair[0],buffer,1) == 0, 61);
    CHECK(DO(3,pair[0],0,0) == 0, 62);
    CHECK(DO(3,pair[0],0,0) == -9, 63);
    CHECK(DO(293,pair,04000,0) == 0, 72);
    long reader=DO(32,pair[0],0,0);
    CHECK(reader >= 0 && DO(292,pair[1],pair[1],02000000) == -22, 73);
    long saved_stdout=DO(32,1,0,0);
    CHECK(saved_stdout>=0 && DO(33,pair[1],1,0) == 1, 74);
    CHECK(DO(1,1,"redirect",8) == 8 && DO(0,reader,buffer,8) == 8 && buffer[0] == 'r', 82);
    CHECK(DO(33,saved_stdout,1,0) == 1 && DO(3,saved_stdout,0,0) == 0, 83);
    CHECK(DO(292,pair[1],pair[0],02000000) == pair[0], 75);
    CHECK(DO(72,pair[0],1,0) == 1, 76);
    CHECK(DO(3,pair[1],0,0) == 0, 77);
    CHECK(DO(1,pair[0],"Q",1) == 1 && DO(0,reader,buffer,1) == 1 && buffer[0] == 'Q', 78);
    CHECK(DO(3,pair[0],0,0) == 0 && DO(0,reader,buffer,1) == 0, 79);
    CHECK(DO(3,reader,0,0) == 0, 80);
    int all[32][2];
    for (word i=0;i<32;++i) CHECK(DO(293,all[i],04000,0) == 0, 64);
    CHECK(DO(293,pair,0,0) == -24, 65);
    for (word i=0;i<32;++i) {
        CHECK(DO(3,all[i][0],0,0) == 0 && DO(3,all[i][1],0,0) == 0, 66);
    }
    // Exhaust descriptors via aliases without falsely closing the original end.
    CHECK(DO(293,pair,04000,0) == 0, 67);
    long aliases[251];
    for (word i=0;i<251;++i) { aliases[i]=DO(72,pair[1],1030,0); CHECK(aliases[i]>=0,68); }
    CHECK(DO(72,aliases[0],1,0) == 1 && DO(72,pair[1],1,0) == 0, 81);
    CHECK(DO(32,pair[1],0,0) == -24, 69);
    for (word i=0;i<251;++i) CHECK(DO(3,aliases[i],0,0) == 0, 70);
    CHECK(DO(3,pair[0],0,0) == 0 && DO(3,pair[1],0,0) == 0, 71);
    DO(1,1,"owned-pipes: PASS\n",18);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall pipe_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
