/* Configured event counters and readiness over public owned descriptors. */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e, word f) {
    register word r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c),
        "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(expr,code) do { if (!(expr)) return code; } while (0)
#define OUT(s) DO(1,1,s,sizeof(s)-1)
struct event { unsigned int events; word data; } __attribute__((packed));
struct pollfd { int fd; unsigned short events, revents; };
static struct event events[32];
static const word readonly_value=9;
static long ctl(int ep,int op,int fd,unsigned int flags,word data) {
    struct event e={flags,data};
    return call(233,ep,op,fd,(word)&e,0,0);
}
static long wait_event(int ep,int maximum,int timeout) {
    return call(232,ep,(word)events,maximum,timeout,0,0);
}
long event_main(word *stack) {
    char **argv=(char **)(stack+1);
    char mode=*stack>1 ? argv[1][0] : 'b';
    word value=0;
    if(mode=='x') {
        CHECK(DO(72,50,1,0)==0 && DO(72,51,1,0)==-9,100);
        CHECK(DO(0,50,&value,8)==8 && value==2,101);
        OUT("owned-events: PASS\n"); return 0;
    }
    if(mode=='d') {
        CHECK(DO(290,0,0,0)==-1 && DO(291,0,0,0)==-1,102);
        CHECK(DO(233,999,1,999)==-1 && DO(232,999,1,1)==-1,103);
        CHECK(call(281,999,1,1,0,0,0)==-1,104);
        OUT("owned-events: PASS\n"); return 0;
    }
    int counter=DO(290,0,04000,0), ep=DO(291,02000000,0,0);
    CHECK(counter==3 && ep==4,10);
    if(mode=='b') {
        CHECK(DO(290,0,2,0)==-22 && DO(291,04000,0,0)==-22,11);
        CHECK(DO(0,counter,&value,8)==-11 && DO(0,counter,&value,7)==-22,12);
        value=~0UL; CHECK(DO(1,counter,&value,8)==-22,13);
        value=~0UL-1; CHECK(DO(1,counter,&value,8)==8,14);
        value=1; CHECK(DO(1,counter,&value,8)==-11,15);
        CHECK(DO(0,counter,&value,16)==8 && value==~0UL-1,16);
        int alias=DO(32,counter,0,0); CHECK(alias==5,17);
        CHECK(DO(72,alias,4,04000)==0 && DO(72,counter,3,0)==(2|04000),18);
        CHECK(DO(72,counter,1032,0)==-9,19);
        value=3; CHECK(DO(1,alias,&value,8)==8,20);
        CHECK(DO(0,counter,&value,8)==8 && value==3,21);
        int semaphore=DO(290,2,04001,0); CHECK(semaphore==6,22);
        CHECK(DO(0,semaphore,&value,8)==8 && value==1,23);
        CHECK(DO(0,semaphore,&value,8)==8 && value==1 && DO(0,semaphore,&value,8)==-11,24);
        struct pollfd p={counter,5,0};
        CHECK(DO(7,&p,1,0)==1 && p.revents==4,25);
        value=2; CHECK(DO(1,counter,&value,8)==8,26);
        CHECK(DO(7,&p,1,0)==1 && p.revents==5,27);
        CHECK(DO(0,ep,&value,8)==-22 && DO(1,ep,&value,8)==-22,28);
    } else if(mode=='l' || mode=='e' || mode=='o') {
        unsigned int flags=1 | (mode=='e' ? 1U<<31 : mode=='o' ? 1U<<30 : 0);
        CHECK(ctl(ep,1,counter,flags,0x123456789abcUL)==0,30);
        CHECK(wait_event(ep,1024,0)==0,31);
        value=3; CHECK(DO(1,counter,&value,8)==8,32);
        CHECK(wait_event(ep,32,0)==1 && events[0].events==1 && events[0].data==0x123456789abcUL,33);
        CHECK(wait_event(ep,1,0)==(mode=='l' ? 1 : 0),34);
        if(mode=='o') {
            CHECK(ctl(ep,3,counter,flags,99)==0,35);
            CHECK(wait_event(ep,1,0)==1 && events[0].data==99,36);
        }
        CHECK(DO(0,counter,&value,8)==8 && value==3,37);
        CHECK(wait_event(ep,1,0)==0,38);
        value=1; CHECK(DO(1,counter,&value,8)==8,39);
        CHECK(wait_event(ep,1,0)==(mode=='o' ? 0 : 1),40);
    } else if(mode=='a') {
        int alias=DO(32,counter,0,0); CHECK(alias==5,41);
        CHECK(ctl(ep,1,counter,1,11)==0 && ctl(ep,1,alias,1,22)==0,42);
        CHECK(ctl(ep,1,counter,1,33)==-17 && ctl(ep,2,ep,0,0)==-1,43);
        value=1; CHECK(DO(1,counter,&value,8)==8,44);
        CHECK(DO(3,counter,0,0)==0 && wait_event(ep,2,0)==2,45);
        CHECK((events[0].data==11 && events[1].data==22) || (events[0].data==22 && events[1].data==11),46);
        CHECK(DO(3,alias,0,0)==0 && wait_event(ep,2,0)==0,47);
        counter=DO(290,1,04000,0); CHECK(counter==3 && wait_event(ep,2,0)==0,48);
        CHECK(ctl(ep,1,counter,1,33)==0 && wait_event(ep,1,0)==1 && events[0].data==33,49);
    } else if(mode=='p') {
        int pipe[2]; CHECK(DO(293,pipe,04000,0)==0,50);
        CHECK(ctl(ep,1,pipe[0],1|0x2000,7)==0 && ctl(ep,1,pipe[1],4,8)==0,51);
        CHECK(wait_event(ep,1,0)==1 && events[0].data==8 && events[0].events==4,52);
        CHECK(DO(1,pipe[1],"X",1)==1 && DO(3,pipe[1],0,0)==0,53);
        CHECK(wait_event(ep,1,0)==1 && events[0].data==7 && events[0].events==17,54);
        char byte=0; CHECK(DO(0,pipe[0],&byte,1)==1 && byte=='X',55);
        CHECK(wait_event(ep,1,0)==1 && events[0].events==16,56);
        int file=DO(2,"/work/file",0102,0600); CHECK(file>=3,57);
        CHECK(ctl(ep,1,file,1,1)==-1 && ctl(ep,1,1,4,1)==-1 && ctl(ep,1,ep,1,1)==-1,58);
    } else if(mode=='f' || mode=='r' || mode=='w') {
        CHECK(DO(72,counter,4,0)==0,60);
        CHECK(ctl(ep,1,counter,mode=='w' ? 4 : 1,42)==0,61);
        if(mode=='w') { value=~0UL-1; CHECK(DO(1,counter,&value,8)==8,62); }
        int child=DO(57,0,0,0); CHECK(child>=0,63);
        if(child==0) {
            CHECK(DO(7,0,0,25)==0,64);
            if(mode=='w') CHECK(DO(0,counter,&value,8)==8 && value==~0UL-1,65);
            else { value=5; CHECK(DO(1,counter,&value,8)==8,66); }
            return 0;
        }
        if(mode=='f') {
            CHECK(wait_event(ep,1,-1)==1 && events[0].data==42 && events[0].events==1,67);
            CHECK(DO(0,counter,&value,8)==8 && value==5,68);
        } else if(mode=='r') {
            CHECK(DO(0,counter,&value,8)==8 && value==5,69);
        } else { value=1; CHECK(DO(1,counter,&value,8)==8,70); }
        int status=-1; CHECK(DO(61,child,&status,0)==child && status==0,71);
    } else if(mode=='t') {
        CHECK(wait_event(ep,1,30)==0,72);
        CHECK(wait_event(ep,0,0)==-22 && wait_event(ep,1,300001)==-22,73);
        word mask=0;
        CHECK(call(14,2,0,(word)&mask,8,0,0)==0,74);
        CHECK(call(281,ep,(word)events,1,0,(word)&mask,8)==0,75);
        mask^=1UL<<(10-1);
        CHECK(call(281,ep,(word)events,1,0,(word)&mask,8)==-95,76);
        CHECK(call(281,ep,(word)events,1,0,1,8)==-14,77);
        CHECK(DO(219,0,0,0)==-38,78);
    } else if(mode=='c') {
        int aliases[17]; aliases[0]=counter;
        for(int i=1;i<17;++i) { aliases[i]=DO(32,counter,0,0); CHECK(aliases[i]>=3,79); }
        for(int i=0;i<16;++i) CHECK(ctl(ep,1,aliases[i],1,i+1)==0,80);
        CHECK(ctl(ep,1,aliases[16],1,17)==-28,81);
        value=1; CHECK(DO(1,counter,&value,8)==8,82);
        word seen=0;
        for(int i=0;i<16;++i) { CHECK(wait_event(ep,1,0)==1,83); seen|=1UL<<events[0].data; }
        CHECK(seen==0x1fffe,84);
        CHECK(DO(3,ep,0,0)==0,85);
        for(int i=1;i<16;++i) CHECK(DO(290,0,0,0)>=3,86);
        CHECK(DO(290,0,0,0)==-24,87);
    } else if(mode=='g') {
        value=7; CHECK(DO(1,counter,&value,8)==8,109);
        CHECK(DO(0,counter,&readonly_value,8)==-14,110);
        CHECK(DO(1,counter,1,8)==-14,111);
        CHECK(ctl(ep,1,counter,1U<<31|1,77)==0,112);
        CHECK(call(232,ep,1,1,0,0,0)==-14,113);
        CHECK(wait_event(ep,1,0)==1 && events[0].data==77,114);
        CHECK(DO(0,counter,&value,8)==8 && value==7,115);
        CHECK(call(233,ep,3,counter,1,0,0)==-14,116);
    } else if(mode=='v') {
        CHECK(DO(32,counter,0,0)==5 && DO(32,counter,0,0)==6 && DO(32,counter,0,0)==7,105);
        CHECK(DO(290,0,0,0)==-24 && DO(32,ep,0,0)==-24,106);
        CHECK(DO(3,5,0,0)==0 && DO(290,1,04000,0)==5,107);
        CHECK(DO(0,5,&value,8)==8 && value==1,108);
    } else if(mode=='k') {
        value=2; CHECK(DO(1,counter,&value,8)==8,88);
        CHECK(DO(33,counter,50,0)==50 && DO(292,counter,51,02000000)==51,89);
        char *args[]={"/bin/fixture","x",0};
        CHECK(DO(59,args[0],args,0)==0,90); return 91;
    } else if(mode=='n') {
        unsigned port=0; for(char *p=argv[2];*p;++p) port=port*10+*p-'0';
        unsigned char addr[16]={2,0,port>>8,port,127,0,0,1};
        int fd=DO(41,2,1,0); CHECK(fd>=3 && DO(42,fd,addr,16)==0,92);
        CHECK(ctl(ep,1,fd,1|0x2000,555)==0,93);
        CHECK(wait_event(ep,1,1000)==1 && events[0].data==555 && (events[0].events&1),94);
        char byte=0; CHECK(DO(0,fd,&byte,1)==1 && byte=='N',95);
        CHECK(wait_event(ep,1,1000)==1 && (events[0].events&0x2000),96);
        CHECK(DO(0,fd,&byte,1)==0 && DO(1,fd,"A",1)==1,97);
    } else return 99;
    OUT("owned-events: PASS\n"); return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall event_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
