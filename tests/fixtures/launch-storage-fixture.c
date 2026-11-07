/* Freestanding workload for real configured-launch memory-storage checks. */
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
static const char immutable[] = "readonly";
static char data[65536];
static char output[65536];
static char meta[256] __attribute__((aligned(8)));
/* Use controlled scratch pages and verify restored path argument registers. */
extern long scratch_stat(word stack, const char *path, char *destination);
__asm__(".global scratch_stat\nscratch_stat:\n"
        "push %r12\npush %r13\npush %r14\nmov %rsp,%r12\n"
        "mov %rsi,%r13\nmov %rdx,%r14\nmov %rdi,%rsp\n"
        "mov %rsi,%rdi\nmov %rdx,%rsi\nmov $4,%rax\nsyscall\n"
        "cmp %r13,%rdi\njne 1f\ncmp %r14,%rsi\nje 2f\n"
        "1: mov $-123,%rax\n2: mov %r12,%rsp\npop %r14\npop %r13\npop %r12\nret\n");
static int equal(const char *a, const char *b) {
    while(*a && *a==*b) { ++a; ++b; } return *a==*b;
}
/* Ordinary data/coherence checks use only valid mappings and trusted buffers. */
static long ordinary_mapping(int unlink_mode) {
    long fd=DO(2,"/work/mapped",0102,0600);
    CHECK(fd==3 && DO(77,fd,8192,0)==0,150);
    CHECK(DO(1,fd,"old",3)==3 && DO(8,fd,4096,0)==4096 && DO(1,fd,"second",6)==6,151);
    long mapped=call(9,0,8192,3,2,fd,0);
    CHECK(mapped>0,152);
    volatile char *bytes=(volatile char *)mapped;
    CHECK(bytes[0]=='o' && bytes[4096]=='s' && bytes[8191]==0 && DO(8,fd,0,1)==4102,153);
    long shared=call(9,0,4096,1,1,fd,4096);
    CHECK(shared>0 && *(volatile char *)shared=='s',154);
    CHECK(DO(8,fd,0,0)==0 && DO(1,fd,"new",3)==3 && bytes[0]=='n',155);
    bytes[0]='C';
    CHECK(DO(8,fd,0,0)==0 && DO(0,fd,output,3)==3 && output[0]=='n',156);
    long child=DO(57,0,0,0); CHECK(child>=0,157);
    if(!child) {
        CHECK(DO(8,fd,4096,0)==4096 && DO(1,fd,"fresh",5)==5,158);
        DO(60,0,0,0); __builtin_unreachable();
    }
    int status=-1; CHECK(DO(61,child,&status,0)==child && status==0 && bytes[4096]=='f' && *(volatile char *)shared=='f',159);
    CHECK(DO(11,mapped,8192,0)==0 && DO(11,shared,4096,0)==0,160);
    CHECK(DO(77,fd,0,0)==0 && DO(77,fd,8192,0)==0 && DO(8,fd,0,0)==0 && DO(1,fd,"kept",4)==4,161);
    mapped=call(9,0,4096,1,2,fd,0); CHECK(mapped>0 && *(volatile char *)mapped=='k',162);
    if(unlink_mode) {
        CHECK(DO(87,"/work/mapped",0,0)==0 && DO(3,fd,0,0)==0,163);
        fd=DO(2,"/work/mapped",0102,0600); CHECK(fd==3 && DO(1,fd,"other",5)==5 && *(volatile char *)mapped=='k',164);
    }
    CHECK(DO(11,mapped,4096,0)==0 && DO(3,fd,0,0)==0,165);
    return 0;
}
static int named(const char *a, const char *b) { while(*a && *a==*b) { ++a; ++b; } return *a==*b; }
static long ordinary_symlinks(void) {
    CHECK(DO(83,"/work/dir",0755,0)==0 && DO(88,"dir","/work/link",0)==0,200);
    CHECK(DO(2,"/work/link/file",0102,0600)==3 && DO(1,3,"data",4)==4 && DO(3,3,0,0)==0,201);
    CHECK(DO(2,"/work/dir/file",0,0)==3 && DO(0,3,output,4)==4 && output[0]=='d' && DO(3,3,0,0)==0,202);
    CHECK(DO(6,"/work/link",meta,0)==0 && (*(word *)(meta+24)&0170000)==0120000 && *(word *)(meta+48)==3,203);
    CHECK(DO(4,"/work/link",meta,0)==0 && (*(word *)(meta+24)&0170000)==0040000,204);
    CHECK(DO(88,"../link","/work/dir/chain",0)==0,205);
    CHECK(DO(2,"/work/dir/chain/../fresh",0101,0600)==3 && DO(3,3,0,0)==0 && DO(4,"/work/fresh",meta,0)==0,206);
    CHECK(DO(88,"/work/dir/file","/work/absolute",0)==0 && DO(2,"/work/absolute",0,0)==3 && DO(0,3,output,4)==4 && output[0]=='d' && DO(3,3,0,0)==0,207);
    CHECK(DO(88,"created","/work/dangling",0)==0 && DO(2,"/work/dangling",0102,0600)==3 && DO(1,3,"new",3)==3 && DO(3,3,0,0)==0,208);
    CHECK(DO(2,"/work/created",0,0)==3 && DO(0,3,output,3)==3 && output[0]=='n' && DO(3,3,0,0)==0,209);
    CHECK(DO(2,"/work/dir",0200000,0)==3 && DO(266,"file",3,"relative")==0,210);
    CHECK(DO(257,3,"relative",0)==4 && DO(0,4,output,4)==4 && output[0]=='d' && DO(3,4,0,0)==0,211);
    long n=DO(217,3,output,sizeof output); CHECK(n>0,213);
    int found=0; for(word at=0;at<(word)n;) {
        unsigned short size=*(unsigned short *)(output+at+16);
        CHECK(size>=24 && at+size<=(word)n,214);
        if(named(output+at+19,"relative")) { CHECK(output[at+18]==10,215); found=1; }
        at+=size;
    }
    CHECK(found && DO(3,3,0,0)==0,216);
    CHECK(DO(82,"/work/link","/work/renamed",0)==0 && DO(87,"/work/renamed",0,0)==0 && DO(4,"/work/dir/file",meta,0)==0,212);
    return 0;
}
static void numbered(char *path, word n) {
    for(int digit=3;digit>=0;--digit) { path[10+digit]='0'+n%10; n/=10; }
}
static long namespace_scale(void) {
    char path[]="/out/file-0000";
    for(word n=0;n<5000;++n) {
        numbered(path,n);
        long fd=DO(2,path,0102,0600); CHECK(fd>=3,160);
        CHECK(DO(1,fd,path+10,4)==4 && DO(3,fd,0,0)==0,161);
    }
    CHECK(DO(2,"/out/overflow",0102,0600)==-28,162);
    for(word n=0;n<5000;++n) {
        numbered(path,n);
        long fd=DO(2,path,0,0); CHECK(fd>=3,163);
        CHECK(DO(0,fd,output,4)==4,164);
        for(word k=0;k<4;++k) CHECK(output[k]==path[10+k],165);
        CHECK(DO(3,fd,0,0)==0,166);
    }
    numbered(path,4999);
    long held=DO(2,path,0,0); CHECK(held>=3 && DO(87,path,0,0)==0,167);
    CHECK(DO(2,"/out/replacement",0102,0600)==-28,168);
    CHECK(DO(3,held,0,0)==0,169);
    long fd=DO(2,"/out/replacement",0102,0600); CHECK(fd>=3 && DO(1,fd,"new",3)==3 && DO(3,fd,0,0)==0,170);
    return 0;
}
static long positioned(void) {
    long fd=DO(2,"/out/positioned",0102,0600); CHECK(fd>=3,160);
    CHECK(DO(1,fd,"ABC",3)==3 && DO(8,fd,1,0)==1,161);
    long alias=DO(32,fd,0,0); CHECK(alias>=3,162);
    CHECK(call(18,alias,(word)"Z",1,2,0,0)==1 && DO(8,fd,0,1)==1,163);
    CHECK(call(18,fd,(word)"x",1,-1,0,0)==-22 && DO(8,alias,0,1)==1,164);
    CHECK(DO(0,alias,output,2)==2 && output[0]=='B' && output[1]=='Z',165);
    CHECK(DO(8,fd,1,0)==1 && call(18,alias,(word)"Q",1,8192,0,0)==1 && DO(8,fd,0,1)==1,166);
    CHECK(call(17,fd,(word)output,2,8191,0,0)==2 && output[0]==0 && output[1]=='Q' && DO(8,alias,0,1)==1,167);
    CHECK(DO(3,fd,0,0)==0 && DO(3,alias,0,0)==0,168);
    fd=DO(2,"/out/positioned",02002,0); CHECK(fd>=3 && DO(8,fd,2,0)==2,169);
    CHECK(call(18,fd,(word)"!",1,0,0,0)==1 && DO(8,fd,0,1)==2,170);
    CHECK(DO(5,fd,meta,0)==0 && *(word *)(meta+48)==8194,171);
    CHECK(call(17,fd,(word)output,1,8193,0,0)==1 && output[0]=='!' && DO(3,fd,0,0)==0,172);
    return 0;
}
static long export_data(const char *mode) {
    CHECK(DO(83,"/out/empty",0755,0)==0,180);
    long fd=DO(2,"/out/product",0101,0700); CHECK(fd==3,181);
    CHECK(DO(1,fd,"result\0data",11)==11 && DO(74,fd,0,0)==0 && DO(75,fd,0,0)==0,182);
    CHECK(DO(3,fd,0,0)==0,183);
    fd=DO(2,"/out/empty-file",0101,0600); CHECK(fd==3 && DO(74,fd,0,0)==0 && DO(3,fd,0,0)==0,184);
    fd=DO(2,"/out",0200000,0); CHECK(fd==3 && DO(74,fd,0,0)==0 && DO(75,fd,0,0)==0 && DO(3,fd,0,0)==0,185);
    CHECK(DO(2,"/out/deleted",0101,0600)==3 && DO(3,3,0,0)==0 && DO(87,"/out/deleted",0,0)==0,186);
    char longpath[208]="/out/";
    for(word i=5;i<125;++i) longpath[i]='a';
    longpath[125]=0; CHECK(DO(83,longpath,0700,0)==0,187);
    longpath[125]='/';
    for(word i=126;i<206;++i) longpath[i]='b';
    longpath[206]=0;
    CHECK(DO(2,longpath,0101,0600)==3 && DO(1,3,"long",4)==4 && DO(3,3,0,0)==0,188);
    if(equal(mode,"child-export")) {
        int ready[2], wait[2];
        CHECK(DO(293,ready,0,0)==0 && DO(293,wait,0,0)==0,189);
        long child=DO(57,0,0,0); CHECK(child>=0,190);
        if(!child) {
            CHECK(DO(3,ready[0],0,0)==0 && DO(3,wait[1],0,0)==0,191);
            fd=DO(2,"/out/child",0101,0600); CHECK(fd>=3,192);
            CHECK(DO(1,fd,"settled",7)==7 && DO(74,fd,0,0)==0 && DO(3,fd,0,0)==0,193);
            CHECK(DO(1,ready[1],"R",1)==1,194);
            DO(0,wait[0],output,1);
            DO(2,"/out/late",0101,0600); return 195;
        }
        CHECK(DO(3,ready[1],0,0)==0 && DO(3,wait[0],0,0)==0,196);
        CHECK(DO(0,ready[0],output,1)==1 && output[0]=='R',197);
    }
    if(equal(mode,"export-wait")) {
        CHECK(DO(1,1,"export-ready\n",13)==13 && DO(0,0,output,1)==1 && output[0]=='G',198);
    }
    return equal(mode,"failed-export") ? 7 : 0;
}
static long checkpoint_data(void) {
    long fd=DO(2,"/work/checkpoint",0102,0600); CHECK(fd==3 && DO(1,fd,"first",5)==5,210);
    long child=DO(57,0,0,0); CHECK(child>=0,211);
    if(!child) {
        long data=DO(2,"/work/child",0101,0600);
        CHECK(data>=3 && DO(1,data,"child",5)==5 && DO(3,data,0,0)==0,212); return 0;
    }
    int status=-1; CHECK(DO(61,child,&status,0)==child && status==0,213);
    CHECK(DO(1,1,"checkpoint-ready\n",17)==17 && DO(0,0,output,1)==1,214);
    CHECK(DO(8,fd,0,0)==0 && DO(1,fd,"second",6)==6,215);
    CHECK(DO(1,1,"checkpoint-ready\n",17)==17 && DO(0,0,output,1)==1,216);
    CHECK(DO(74,fd,0,0)==0 && DO(75,fd,0,0)==0 && DO(3,fd,0,0)==0,217);
    return 0;
}
static long task_events_data(void) {
    for(word n=0;n<10000;++n) CHECK(DO(39,0,0,0)>0,218);
    CHECK(DO(1,1,"events: PASS\n",13)==13,219); return 0;
}
static long restore_data(int large) {
    if(large) {
        long fd=DO(2,"/out/nested/data",0,0); CHECK(fd==3,220);
        word offset=0;
        while(offset<8193) {
            long count=DO(0,fd,output+offset,8193-offset);
            CHECK(count>0 && (word)count<=8193-offset,221); offset+=(word)count;
        }
        CHECK(DO(0,fd,output,1)==0,221);
        for(word i=0;i<8193;++i) CHECK(output[i]==(char)(i%251),222);
        CHECK(DO(3,fd,0,0)==0,223);
        CHECK(DO(4,"/out/nested",meta,0)==0 && (*(word *)(meta+24)&0777)==0700,224);
    } else {
        long fd=DO(2,"/out/product",0,0); CHECK(fd==3,225);
        CHECK(DO(0,fd,output,sizeof output)==11,226);
        const char expected[]="result\0data";
        for(word i=0;i<11;++i) CHECK(output[i]==expected[i],227);
        CHECK(DO(5,fd,meta,0)==0 && (*(word *)(meta+24)&0777)==0700 && DO(3,fd,0,0)==0,228);
        CHECK(DO(4,"/out/empty",meta,0)==0 && (*(word *)(meta+24)&0170000)==0040000,229);
        CHECK(DO(2,"/out/empty-file",0,0)==3 && DO(0,3,output,1)==0 && DO(3,3,0,0)==0,230);
        char path[208]="/out/";
        for(word i=5;i<125;++i) path[i]='a';
        path[125]='/';
        for(word i=126;i<206;++i) path[i]='b';
        path[206]=0;
        CHECK(DO(2,path,0,0)==3 && DO(0,3,output,4)==4 && output[0]=='l' && DO(3,3,0,0)==0,231);
        CHECK(DO(2,"/out/product",01001,0600)==3 && DO(1,3,"changed",7)==7 && DO(3,3,0,0)==0,232);
    }
    CHECK(DO(1,1,"restored: PASS\n",15)==15,233); return 0;
}
static long archive_links(int restore) {
    char path[208]="/out/";
    for(word i=5;i<125;++i) path[i]='a';
    path[125]='/';
    for(word i=126;i<206;++i) path[i]='b';
    path[206]=0;
    if(!restore) {
        long status=export_data("export"); CHECK(status==0,status);
        CHECK(DO(86,"/out/product","/out/product-alias",0)==0 && DO(86,path,"/out/long-alias",0)==0,234);
        CHECK(DO(88,"product","/out/product-link",0)==0 && DO(88,path,"/out/long-link",0)==0,235);
        CHECK(DO(2,"/out/temporary",0101,0600)==3 && DO(1,3,"orphan",6)==6 && DO(3,3,0,0)==0,236);
        CHECK(DO(86,"/out/temporary","/out/surviving",0)==0 && DO(87,"/out/temporary",0,0)==0,237);
        long times[4]={11,123,123456789,987654321};
        CHECK(call(280,-100,(word)"/out/product",(word)times,0,0,0)==0,85);
        times[2]=222; times[3]=333;
        CHECK(call(280,-100,(word)"/out/product-link",(word)times,0x100,0,0)==0,86);
    } else {
        CHECK(DO(4,"/out/product",meta,0)==0 && *(long *)(meta+72)==0 && *(long *)(meta+88)==123456789 && *(long *)(meta+96)==0,87);
        CHECK(DO(6,"/out/product-link",meta,0)==0 && *(long *)(meta+88)==222 && *(long *)(meta+96)==0,88);
        long status=restore_data(0); CHECK(status==0,status);
        CHECK(DO(4,"/out/product",meta,0)==0 && *(word *)(meta+16)==2,238);
        word inode=*(word *)(meta+8);
        CHECK(DO(4,"/out/product-alias",meta,0)==0 && *(word *)(meta+8)==inode && *(word *)(meta+16)==2,239);
        CHECK(DO(2,"/out/product-alias",0,0)==3 && DO(0,3,output,7)==7 && output[0]=='c' && DO(3,3,0,0)==0,240);
        CHECK(DO(2,"/out/product-link",0,0)==3 && DO(0,3,output,7)==7 && output[0]=='c' && DO(3,3,0,0)==0,241);
        CHECK(DO(2,"/out/long-alias",0,0)==3 && DO(0,3,output,4)==4 && output[0]=='l' && DO(3,3,0,0)==0,242);
        CHECK(DO(2,"/out/long-link",0,0)==3 && DO(0,3,output,4)==4 && output[0]=='l' && DO(3,3,0,0)==0,243);
        CHECK(DO(2,"/out/surviving",0,0)==3 && DO(0,3,output,6)==6 && output[0]=='o' && DO(3,3,0,0)==0,244);
    }
    return 0;
}
static long restore_namespace(void) {
    char path[]="/out/file-0000";
    for(word n=0;n<4999;++n) {
        numbered(path,n); long fd=DO(2,path,0,0); CHECK(fd==3,245);
        CHECK(DO(0,fd,output,4)==4,246);
        for(word i=0;i<4;++i) CHECK(output[i]==path[10+i],247);
        CHECK(DO(3,fd,0,0)==0,248);
    }
    CHECK(DO(2,"/out/replacement",0,0)==3 && DO(0,3,output,3)==3 && output[0]=='n' && DO(3,3,0,0)==0,249);
    CHECK(DO(1,1,"restored: PASS\n",15)==15,250); return 0;
}
static long restore_big(void) {
    long fd=DO(2,"/out/big",0,0); CHECK(fd==3 && DO(5,fd,meta,0)==0 && *(word *)(meta+48)==2147483649UL,251);
    CHECK(DO(0,fd,output,1)==1 && output[0]==0,252);
    CHECK(DO(8,fd,2147483647UL,0)==2147483647UL && DO(0,fd,output,2)==2 && output[0]==0 && output[1]=='Z',253);
    CHECK(DO(3,fd,0,0)==0 && DO(1,1,"restored: PASS\n",15)==15,254); return 0;
}
static long timestamp_data(int ordinary) {
    long fd=DO(2,"/work/time",0102,0600); CHECK(fd==3,70);
    CHECK(DO(86,"/work/time","/work/time-alias",0)==0 && DO(88,"time","/work/time-link",0)==0,71);
    long times[4]={11,123,123456789,987654321};
    CHECK(call(280,fd,0,(word)times,0,0,0)==0 && DO(5,fd,meta,0)==0,72);
    CHECK(*(long *)(meta+72)==11 && *(long *)(meta+80)==123 && *(long *)(meta+88)==123456789 && *(long *)(meta+96)==987654321,73);
    CHECK(DO(4,"/work/time-alias",meta,0)==0 && *(long *)(meta+88)==123456789,74);
    CHECK(call(332,-100,(word)"/work/time",0,0x7ff,(word)meta,0)==0 && *(long *)(meta+112)==123456789 && *(unsigned *)(meta+120)==987654321,75);
    times[0]=99; times[1]=1073741822; times[3]=555;
    CHECK(call(280,fd,0,(word)times,0,0,0)==0 && DO(5,fd,meta,0)==0 && *(long *)(meta+72)==11 && *(long *)(meta+80)==123 && *(long *)(meta+96)==555,76);
    if(!ordinary) {
        times[3]=1000000000;
        CHECK(call(280,fd,0,(word)times,0,0,0)==-22 && call(280,fd,0,1,0,0,0)==-14,77);
    }
    times[3]=1073741823;
    CHECK(call(280,fd,0,(word)times,0,0,0)==0 && DO(5,fd,meta,0)==0 && *(long *)(meta+72)==11 && *(long *)(meta+88)>1000000000,78);
    CHECK(call(280,fd,0,0,0,0,0)==0 && DO(5,fd,meta,0)==0,89);
    CHECK(*(long *)(meta+72)>1000000000 && *(long *)(meta+72)==*(long *)(meta+88) && *(long *)(meta+80)==*(long *)(meta+96),90);
    times[0]=11; times[1]=123; times[2]=123456789; times[3]=987654321;
    CHECK(call(280,-100,(word)"/work/time-alias",(word)times,0,0,0)==0,79);
    times[2]=222; times[3]=333;
    CHECK(call(280,-100,(word)"/work/time-link",(word)times,0x100,0,0)==0,80);
    CHECK(DO(6,"/work/time-link",meta,0)==0 && *(long *)(meta+88)==222 && DO(5,fd,meta,0)==0 && *(long *)(meta+88)==123456789,81);
    CHECK(DO(87,"/work/time",0,0)==0,82);
    times[0]=13; times[1]=456; times[2]=123456789; times[3]=987654321;
    CHECK(call(280,fd,0,(word)times,0,0,0)==0 && DO(4,"/work/time-alias",meta,0)==0 && *(long *)(meta+72)==13,83);
    CHECK(DO(3,fd,0,0)==0,84); return 0;
}
/* Valid, stable buffers exercise owned I/O without relying on native transfers. */
static char large_io[2*1024*1024+37];
static long ordinary_vectors(void) {
    long fd=DO(2,"/out/vectors",0102,0600); CHECK(fd>=3,180);
    word vectors[32]={0};
    CHECK(DO(20,fd,vectors,0)==0 && DO(19,fd,vectors,0)==0,181);
    vectors[0]=(word)"ab";vectors[1]=2;vectors[2]=0;vectors[3]=0;
    vectors[4]=(word)"cde";vectors[5]=3;
    CHECK(DO(20,fd,vectors,3)==5 && DO(8,fd,0,1)==5,182);
    long alias=DO(32,fd,0,0);CHECK(alias>=3 && DO(8,alias,0,0)==0,183);
    vectors[0]=(word)output;vectors[1]=1;vectors[4]=(word)(output+1);vectors[5]=8;
    CHECK(DO(19,alias,vectors,3)==5 && DO(8,fd,0,1)==5,184);
    CHECK(output[0]=='a' && output[1]=='b' && output[4]=='e' && DO(19,fd,vectors,3)==0,185);
    for(word i=0;i<16;++i) { data[i]=(char)('A'+i);vectors[2*i]=(word)(data+i);vectors[2*i+1]=1; }
    CHECK(DO(20,fd,vectors,16)==16 && DO(8,fd,5,0)==5,186);
    for(word i=0;i<16;++i) vectors[2*i]=(word)(output+i);
    CHECK(DO(19,fd,vectors,16)==16,187);
    for(word i=0;i<16;++i) CHECK(output[i]==data[i],188);
    CHECK(DO(20,fd,vectors,17)==-22 && DO(8,fd,0,1)==21,189);
    for(word i=0;i<8192;++i) data[i]=(char)(i%251);
    vectors[0]=(word)data;vectors[1]=4090;vectors[2]=(word)(data+4090);vectors[3]=4102;
    CHECK(DO(77,fd,0,0)==0 && DO(8,fd,0,0)==0 && DO(20,fd,vectors,2)==4096,190);
    CHECK(DO(5,fd,meta,0)==0 && *(word *)(meta+48)==4096 && DO(8,alias,0,1)==4096,191);
    CHECK(DO(8,fd,0,0)==0,192);
    vectors[0]=(word)output;vectors[1]=4090;vectors[2]=(word)(output+4090);vectors[3]=4102;
    CHECK(DO(19,alias,vectors,2)==4096 && DO(8,fd,0,1)==4096,193);
    for(word i=0;i<4096;++i) CHECK(output[i]==data[i],194);
    CHECK(DO(3,fd,0,0)==0 && DO(3,alias,0,0)==0,195);
    return 0;
}
static long ordinary_large_io(void) {
    const word mib=1024*1024;
    for(word i=0;i<sizeof large_io;++i) large_io[i]=(char)(i%251);
    long fd=DO(2,"/out/large-io",0102,0600);CHECK(fd>=3,196);
    CHECK(DO(1,fd,large_io,sizeof large_io)==mib && DO(8,fd,0,1)==mib,197);
    CHECK(DO(1,fd,large_io+mib,sizeof large_io-mib)==mib,198);
    CHECK(DO(1,fd,large_io+2*mib,37)==37 && DO(5,fd,meta,0)==0,199);
    CHECK(*(word *)(meta+48)==sizeof large_io && DO(8,fd,0,0)==0,200);
    for(word i=0;i<sizeof large_io;++i) large_io[i]=0;
    word done=0;
    while(done<sizeof large_io) {
        long n=DO(0,fd,large_io+done,sizeof large_io-done);
        CHECK(n>0 && n<=4096,201);
        for(long i=0;i<n;++i) CHECK(large_io[done+i]==(char)((done+i)%251),202);
        done+=(word)n;
    }
    CHECK(DO(0,fd,output,sizeof output)==0,203);
    long alias=DO(32,fd,0,0);CHECK(alias>=3 && DO(8,fd,17,0)==17,204);
    CHECK(call(18,alias,(word)large_io,sizeof large_io,3*mib,0,0)==mib && DO(8,fd,0,1)==17,205);
    CHECK(call(17,fd,(word)output,4096,4*mib-4096,0,0)==4096 && DO(8,alias,0,1)==17,206);
    for(word i=0;i<4096;++i) CHECK(output[i]==large_io[mib-4096+i],207);
    CHECK(DO(3,fd,0,0)==0 && DO(3,alias,0,0)==0,208);
    return 0;
}
static long ownership(int full) {
    long fd=DO(2,"/work/owner",0102,0640); CHECK(fd>=3,100);
    CHECK(DO(1,fd,"root",4)==4 && DO(86,"/work/owner","/work/alias",0)==0,101);
    CHECK(DO(93,fd,0,-1)==0 && DO(92,"/work/alias",-1,0)==0,102);
    long alias=DO(32,fd,0,0); CHECK(alias>=3 && DO(3,fd,0,0)==0,103);
    CHECK(DO(88,"owner","/work/owner-link",0)==0 && DO(94,"/work/owner-link",0,0)==0,104);
    CHECK(call(260,-100,(word)"/work/owner-link",-1,0,0x100,0)==0,105);
    CHECK(call(260,alias,(word)"",0,-1,0x1000,0)==0,106);
    long dir=DO(2,"/work",0200000,0); CHECK(dir>=3,107);
    CHECK(call(260,dir,(word)"alias",0,0,0,0)==0 && DO(93,dir,-1,-1)==0,108);
    CHECK(DO(5,alias,meta,0)==0 && *(unsigned *)(meta+28)==0 && *(unsigned *)(meta+32)==0,109);
    CHECK(*(word *)(meta+16)==2 && *(word *)(meta+48)==4 && (*(unsigned *)(meta+24)&0777)==0640,110);
    CHECK(call(332,alias,(word)"",0x1000,0x7ff,(word)meta,0)==0 && *(unsigned *)(meta+20)==0 && *(unsigned *)(meta+24)==0,111);
    CHECK(DO(87,"/work/owner",0,0)==0 && DO(87,"/work/alias",0,0)==0 && DO(93,alias,0,0)==0,112);
    CHECK(DO(8,alias,0,0)==0 && DO(0,alias,output,4)==4 && output[0]=='r' && output[3]=='t',113);
    if(full) {
        CHECK(DO(88,"missing","/work/dangling",0)==0 && DO(94,"/work/dangling",0,0)==0,114);
        CHECK(DO(92,"/work/dangling",0,0)==-2 && call(260,-100,(word)"/work/dangling",0,0,0x100,0)==0,115);
        CHECK(call(260,alias,(word)"",0,0,0,0)==-2 && DO(93,alias,1,0)==-95,116);
        CHECK(DO(92,"/work/missing",0,0)==-2 && DO(92,1,0,0)==-14,117);
        CHECK(call(260,dir,(word)"missing",0,0,2,0)==-22 && DO(93,0,0,0)==-1,118);
    }
    CHECK(DO(3,dir,0,0)==0 && DO(3,alias,0,0)==0,119);
    return 0;
}
long storage_main(word *stack)
{
    word argc = *stack;
    char **argv = (char **)(stack + 1);
    if(argc>1 && equal(argv[1],"timestamps")) return timestamp_data(0);
    if(argc>1 && equal(argv[1],"ordinary-times")) return timestamp_data(1);
    if(argc>1 && equal(argv[1],"archive-create")) return archive_links(0);
    if(argc>1 && equal(argv[1],"restore-links")) return archive_links(1);
    if(argc>1 && equal(argv[1],"restore-namespace")) return restore_namespace();
    if(argc>1 && equal(argv[1],"restore-big")) return restore_big();
    if(argc>1 && equal(argv[1],"namespace")) return namespace_scale();
    if(argc>1 && equal(argv[1],"ordinary-vectors")) return ordinary_vectors();
    if(argc>1 && equal(argv[1],"ordinary-large-io")) return ordinary_large_io();
    if(argc>1 && equal(argv[1],"positioned")) return positioned();
    if(argc>1 && equal(argv[1],"checkpoint")) return checkpoint_data();
    if(argc>1 && equal(argv[1],"events")) return task_events_data();
    if(argc>1 && equal(argv[1],"restore")) return restore_data(0);
    if(argc>1 && equal(argv[1],"restore-large")) return restore_data(1);
    if(argc>1 && (equal(argv[1],"flush") || equal(argv[1],"export") || equal(argv[1],"export-wait") || equal(argv[1],"failed-export") || equal(argv[1],"child-export"))) return export_data(argv[1]);
    if(argc>1 && named(argv[1],"ordinary-ownership"))return ownership(0);
    if(argc>1 && named(argv[1],"ownership"))return ownership(1);
    if (argc > 1 && argv[1][0] == 'v') {
        long fd=DO(2,"/work/probe",0102|0400,0600);
        CHECK(fd>=3 && DO(1,fd,"ok",2)==2,145);
        CHECK(DO(21,"/work/probe",0,0)==0 && DO(21,"/work/probe",6,0)==0,146);
        CHECK(DO(21,"/work/probe",1,0)==-13,147);
        CHECK(DO(269,-100,"/work/probe",4)==0,148);
        CHECK(call(439,fd,(word)"",4,0x1000,0,0)==0,149);
        CHECK(DO(91,fd,0700,0)==0 && DO(21,"/work/probe",1,0)==0,150);
        CHECK(DO(89,"/work/probe",output,16)==-22,151);
        CHECK(call(267,-100,(word)"/work/probe",(word)output,16,0,0)==-22,152);
        long reader=DO(2,"/work/probe",0400,0);
        CHECK(reader>=3 && DO(0,reader,output,2)==2 && output[0]=='o',153);
        CHECK(DO(3,reader,0,0)==0 && DO(3,fd,0,0)==0,154);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'g') {
        long fd=DO(2,"/out/growing",0102,0600);
        CHECK(fd>=3,120);
        for(word i=0;i<4096;++i) data[i]=(char)(i%251);
        for(word i=0;i<32;++i) CHECK(DO(1,fd,data,4096)==4096,121);
        CHECK(DO(5,fd,meta,0)==0 && *(word *)(meta+48)==131072,122);
        CHECK(DO(8,fd,0,0)==0,123);
        for(word n=0;n<32;++n) {
            CHECK(DO(0,fd,output,4096)==4096,124);
            for(word i=0;i<4096;++i) CHECK(output[i]==data[i],125);
        }
        CHECK(DO(8,fd,2*1024*1024,0)==2*1024*1024 && DO(1,fd,"Q",1)==1,126);
        CHECK(DO(8,fd,2*1024*1024-1,0)==2*1024*1024-1,127);
        CHECK(DO(0,fd,output,2)==2 && output[0]==0 && output[1]=='Q',128);
        long alias=DO(32,fd,0,0);
        CHECK(alias>=3 && DO(77,alias,3,0)==0 && DO(77,fd,8192,0)==0,129);
        CHECK(DO(8,alias,0,0)==0 && DO(0,fd,output,4096)==4096,130);
        for(word i=0;i<4096;++i) CHECK(output[i]==(i<3?data[i]:0),131);
        CHECK(DO(0,alias,output,4096)==4096,132);
        for(word i=0;i<4096;++i) CHECK(output[i]==0,133);
        CHECK(DO(8,fd,0,0)==0,134);
        long child=DO(57,0,0,0);
        if(child==0) { long code=DO(1,alias,"Z",1)==1?17:1; DO(60,code,0,0); __builtin_unreachable(); }
        int status=0;
        CHECK(child>1 && DO(61,child,&status,0)==child && status==(17<<8),135);
        CHECK(DO(8,fd,0,1)==1 && DO(8,fd,0,0)==0,136);
        CHECK(DO(0,fd,output,1)==1 && output[0]=='Z',137);
        CHECK(DO(87,"/out/growing",0,0)==0 && DO(3,fd,0,0)==0,138);
        CHECK(DO(8,alias,0,0)==0 && DO(0,alias,output,1)==1 && output[0]=='Z',139);
        CHECK(DO(3,alias,0,0)==0,140);
        return 0;
    }
    if (argc > 1 && equal(argv[1],"ordinary-mapping")) return ordinary_mapping(0);
    if (argc > 1 && equal(argv[1],"ordinary-unlinked-mapping")) return ordinary_mapping(1);
    if (argc > 1 && equal(argv[1],"mapping")) {
        long fd=DO(2,"/work/mapped",0102,0600);
        CHECK(fd==3 && DO(77,fd,8192,0)==0,110);
        CHECK(DO(1,fd,"old",3)==3 && DO(8,fd,4096,0)==4096 && DO(1,fd,"second",6)==6,111);
        CHECK(call(9,0,8192,3,1,fd,0)==-95,112);
        long shared=call(9,0,4096,1,1,fd,0);
        CHECK(shared>0 && *(volatile char *)shared=='o',132);
        CHECK(DO(10,shared,4096,3)==-13 && DO(11,shared,4096,0)==0,133);
        CHECK(call(9,0,8192,3,2,fd,1)==-22,113);
        word stack_pointer; __asm__ volatile("mov %%rsp,%0":"=r"(stack_pointer));
        CHECK(call(9,(stack_pointer-16384)&~4095UL,32768,3,0x12,fd,0)==-95,134);
        long mapped=call(9,0,8192,3,2,fd,0);
        CHECK(mapped>0,114);
        volatile char *bytes=(volatile char *)mapped;
        CHECK(bytes[0]=='o' && bytes[4096]=='s' && bytes[8191]==0,115);
        CHECK(DO(8,fd,0,1)==4102,116);
        CHECK(DO(8,fd,0,0)==0 && DO(1,fd,"new",3)==3 && bytes[0]=='n',117);
        bytes[0]='C';
        CHECK(DO(8,fd,0,0)==0 && DO(0,fd,output,3)==3 && output[0]=='n',118);
        long child=DO(57,0,0,0);
        CHECK(child>=0,119);
        if (!child) {
            CHECK(DO(8,fd,4096,0)==4096 && DO(1,fd,"fresh",5)==5,120);
            DO(60,0,0,0); __builtin_unreachable();
        }
        int status;
        CHECK(DO(61,child,&status,0)==child && status==0 && bytes[4096]=='f',121);
        child=DO(57,0,0,0);
        CHECK(child>=0,122);
        if (!child) {
            CHECK(DO(77,fd,0,0)==0,123);
            volatile char fault=bytes[4096]; (void)fault;
            DO(60,99,0,0); __builtin_unreachable();
        }
        CHECK(DO(61,child,&status,0)==child && (status&127)==7,124);
        CHECK(DO(77,fd,8192,0)==0 && bytes[4096]==0,125);
        CHECK(DO(11,mapped,8192,0)==0,126);
        CHECK(DO(8,fd,0,0)==0 && DO(1,fd,"kept",4)==4,127);
        mapped=call(9,0,4096,1,2,fd,0); CHECK(mapped>0,128);
        CHECK(DO(87,"/work/mapped",0,0)==0 && DO(3,fd,0,0)==0,129);
        fd=DO(2,"/work/mapped",0102,0600);
        CHECK(fd==3 && DO(1,fd,"other",5)==5 && *(volatile char *)mapped=='k',130);
        CHECK(DO(11,mapped,4096,0)==0 && DO(3,fd,0,0)==0,131);
        CHECK(DO(1,1,"mapping-ready\n",14)==14 && DO(0,0,output,1)==1 && output[0]=='G',135);
        return 0;
    }
    if (argc > 1 && named(argv[1],"ordinary-symlinks")) return ordinary_symlinks();
    if (argc > 1 && named(argv[1],"symlinks")) {
        CHECK(DO(83,"/work/dir",0755,0)==0,166);
        CHECK(DO(88,"dir","/work/link",0)==0,167);
        CHECK(DO(84,"/work/link/",0,0)==-20 && DO(87,"/work/link/",0,0)==-20,199);
        CHECK(DO(82,"/work/link/","/work/moved",0)==-20 && DO(4,"/work/dir",meta,0)==0,200);
        CHECK(DO(83,"/work/new/",0755,0)==0 && DO(84,"/work/new/",0,0)==0,201);
        CHECK(DO(84,"/work/link/.",0,0)==-22 && DO(82,"/work/link/.","/work/moved",0)==-22,202);
        CHECK(DO(4,"/work/dir",meta,0)==0,203);
        CHECK(DO(2,"/work/link/file",0102,0600)==3 && DO(1,3,"data",4)==4 && DO(3,3,0,0)==0,168);
        CHECK(DO(2,"/work/dir/file",0,0)==3 && DO(0,3,output,4)==4 && output[0]=='d' && DO(3,3,0,0)==0,169);
        CHECK(DO(6,"/work/link",meta,0)==0 && (*(word *)(meta+24)&0170000)==0120000,170);
        CHECK(DO(4,"/work/link",meta,0)==0 && (*(word *)(meta+24)&0170000)==0040000,171);
        CHECK(DO(89,"/work/link",output,2)==2 && output[0]=='d' && output[1]=='i',172);
        CHECK(DO(2,"/work/link",0400000,0)==-40 && DO(2,"/work/link",0301,0600)==-17,173);
        CHECK(DO(88,"../link","/work/dir/chain",0)==0,174);
        CHECK(DO(2,"/work/dir/chain/../fresh",0101,0600)==3 && DO(3,3,0,0)==0,175);
        CHECK(DO(4,"/work/fresh",meta,0)==0 && DO(4,"/work/dir/fresh",meta,0)==-2,176);
        CHECK(DO(88,"/image","/work/image",0)==0 && DO(2,"/work/image",0,0)==3,177);
        CHECK(DO(0,3,output,9)==9 && output[0]=='i' && DO(3,3,0,0)==0,216);
        CHECK(DO(88,"/","/work/root",0)==0 && DO(2,"/work/root/escape",0101,0600)<0,178);
        CHECK(DO(2,"/work/root/../image",0,0)<0 && DO(2,"/work/link/../../image",0,0)==3 && DO(3,3,0,0)==0,179);
        CHECK(DO(2,"/work/dir",0200000,0)==3,180);
        CHECK(DO(266,"file",3,"relative")==0,181);
        CHECK(call(267,3,(word)"relative",(word)output,64,0,0)==4 && output[0]=='f',182);
        CHECK(call(262,3,(word)"relative",(word)meta,0x100,0,0)==0 && (*(word *)(meta+24)&0170000)==0120000,183);
        CHECK(DO(257,3,"relative",0)==4 && DO(0,4,output,4)==4 && output[0]=='d' && DO(3,4,0,0)==0,184);
        CHECK(DO(3,3,0,0)==0,185);
        CHECK(DO(82,"/work/link","/work/renamed",0)==0 && DO(87,"/work/renamed",0,0)==0,186);
        CHECK(DO(4,"/work/dir/file",meta,0)==0,187);
        CHECK(DO(88,"cycle","/work/cycle",0)==0 && DO(2,"/work/cycle",0,0)==-40,188);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'n') {
        CHECK(DO(2, "/work/new", 0101, 0644) < 0, 10);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'p') {
        CHECK(DO(2, "/work/file", 0102, 0644) >= 3, 80);
        CHECK(DO(2, "/work/file/../created", 0102, 0644) == -20, 81);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'm') {
        CHECK(DO(2, "/work/file", 0102, 0644) >= 3, 85);
        CHECK(DO(4, "/work/missing/../file", meta, 0) == -2, 82);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'i') {
        CHECK(DO(2, "/image/../work/created", 0102, 0644) == -20, 83);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'a') {
        CHECK(DO(2, "/image-link/existing", 0, 0) == -2, 84);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'c') {
        long fd = DO(2, "/virtual/../image", 0, 0);
        CHECK(fd >= 3 && fd < 256, 86);
        CHECK(DO(0, fd, output, 15) == 15 && output[0] == 'i', 87);
        CHECK(call(262,fd,(word)"",(word)meta,0x1000,0,0) == 0, 88);
        CHECK(*(word *)(meta+48) == 15, 89);
        CHECK(DO(3, fd, 0, 0) == 0, 90);
        CHECK(DO(89, "/work/existing", output, 256) == -2, 91);
        CHECK(DO(21, "/work/existing", 0, 0) == -2, 92);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 's') {
        long pages = call(9,0,8192,3,0x22,-1,0);
        CHECK(pages > 0, 93);
        unsigned char *bytes = (unsigned char *)pages;
        for (word i = 0; i < 8192; ++i) bytes[i] = 0x5a;
        CHECK(scratch_stat(pages+512, "/virtual/../image", meta) == 0, 94);
        CHECK(*(word *)(meta+48) == 15, 95);
        for (word i = 0; i < 257; ++i) CHECK(bytes[i] == 0x5a, 96);
        CHECK(scratch_stat(pages+512, "/virtual/../image", (char *)(pages+16)) == -14, 97);
        CHECK(DO(10, pages+4096, 4096, 1) == 0, 98);
        CHECK(scratch_stat(pages+4608, "/virtual/../image", meta) == -14, 99);
        CHECK(scratch_stat(pages+4480, "/virtual/../image", meta) == -14, 100);
        for (word i = 0; i < 8192; ++i) CHECK(bytes[i] == 0x5a, 101);
        CHECK(DO(11, pages, 8192, 0) == 0, 102);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 't') {
        long fd = DO(2, "/work/file", 0102, 0644);
        CHECK(fd >= 3, 103);
        CHECK(call(262,-100,(word)"/work/file",(word)meta,0x1900,0,0) == 0, 104);
        CHECK(call(262,fd,(word)"",(word)meta,0x1900,0,0) == 0, 105);
        CHECK(call(332,-100,(word)"/work/file",0x2900,0x7ff,(word)meta,0) == 0, 106);
        CHECK(call(332,fd,(word)"",0x5900,0x7ff,(word)meta,0) == 0, 107);
        CHECK(call(332,-100,(word)"/work/file",0x6000,0x7ff,(word)meta,0) == -22, 108);
        CHECK(call(332,fd,(word)"",0x1000,0x80000000,(word)meta,0) == -22, 109);
        CHECK(call(332,-100,(word)"/work/file",0,0x80000000,(word)meta,0) == -22, 110);
        return 0;
    }
    if (argc > 1 && argv[1][0] == 'q') {
        char path[] = "/out/file-00";
        for (word i = 0; i < 99; ++i) {
            path[10] = '0' + i / 10;
            path[11] = '0' + i % 10;
            long fd = DO(2, path, 0101, 0644);
            if (fd == -28) return i > 0 && i < 32 ? 0 : 61;
            CHECK(fd >= 3, 62);
            CHECK(DO(3, fd, 0, 0) == 0, 63);
        }
        return 64;
    }
    if (argc > 1 && argv[1][0] == 'b') {
        const word mib=1024*1024;
        long a=DO(2,"/out/a",0102,0600), b=DO(2,"/out/b",0102,0600), c=DO(2,"/out/c",0102,0600);
        CHECK(a>=3 && b>=3 && c>=3,75);
        CHECK(DO(77,a,16*mib-4096,0)==0 && DO(8,a,16*mib-4096,0)==16*mib-4096,209);
        CHECK(DO(1,a,data,8192)==4096 && DO(1,a,data,1)==-28,210);
        CHECK(DO(5,a,meta,0)==0 && *(word *)(meta+48)==16*mib && DO(8,a,0,1)==16*mib,211);
        CHECK(DO(77,a,0,0)==0 && DO(8,a,0,0)==0,212);
        CHECK(DO(77,a,12*mib,0)==0 && DO(77,b,8*mib,0)==-28,76);
        CHECK(DO(5,b,meta,0)==0 && *(word *)(meta+48)==0,77);
        CHECK(DO(77,a,4*mib,0)==0 && DO(77,b,8*mib,0)==0,78);
        CHECK(DO(77,c,5*mib,0)==-28,79);
        CHECK(DO(3,a,0,0)==0 && DO(87,"/out/a",0,0)==0 && DO(77,c,5*mib,0)==0,80);
        CHECK(DO(1,c,"K",1)==1,141);
        CHECK(DO(87,"/out/b",0,0)==0 && DO(77,c,9*mib,0)==-28,81);
        CHECK(call(18,c,(word)"x",1,9*mib,0,0)==-28 && DO(8,c,0,1)==1,173);
        CHECK(DO(8,c,0,1)==1 && DO(5,c,meta,0)==0 && *(word *)(meta+48)==5*mib,142);
        CHECK(DO(8,c,0,0)==0 && DO(0,c,output,1)==1 && output[0]=='K',143);
        CHECK(DO(3,b,0,0)==0 && DO(77,c,9*mib,0)==0,82);
        long alias=DO(32,c,0,0), d=DO(2,"/out/d",0102,0600);
        CHECK(alias>=3 && d>=3 && DO(87,"/out/c",0,0)==0,83);
        CHECK(DO(77,d,16*mib,0)==-28 && DO(3,c,0,0)==0 && DO(77,d,16*mib,0)==-28,84);
        CHECK(DO(3,alias,0,0)==0 && DO(77,d,16*mib,0)==0,85);
        CHECK(DO(8,d,16*mib-1,0)==16*mib-1 && DO(0,d,output,1)==1 && output[0]==0,86);
        CHECK(DO(1,d,"!",1)==-28 && DO(5,d,meta,0)==0 && *(word *)(meta+48)==16*mib,87);
        CHECK(DO(8,d,0,1)==16*mib,144);
        CHECK(DO(77,d,-1,0)==-22 && DO(5,d,meta,0)==0 && *(word *)(meta+48)==16*mib,88);
        return 0; // Teardown must release a still-linked full-quota mapping.
    }
    word limits[2];
    CHECK(call(302,0,7,0,(word)limits,0,0) == 0, 65);
    CHECK(limits[0] <= 256 && limits[1] <= 256, 66);
    limits[0] = limits[1] = 1048577;
    CHECK(call(302,0,7,(word)limits,0,0,0) < 0, 67);
    CHECK(DO(4, "/work", meta, 0) == 0, 11);
    CHECK((*(unsigned int *)(meta + 24) & 0170000) == 0040000, 12);
    CHECK(DO(2, "/work/existing", 0, 0) == -2, 13);
    CHECK(DO(2, "/image", 1, 0) < 0, 14);
    CHECK(DO(2, "/out/missing", 0, 0) == -2, 15);
    CHECK(DO(2, 1, 0, 0) == -14, 16);
    CHECK(DO(83, "/work/build/nested", 0755, 0) == 0, 17);
    long fd = call(257, -100, (word)"build/nested/file", 0102|02000000, 0644, 0, 0);
    CHECK(fd == 3, 18);
    CHECK(DO(1, fd, "hello", 5) == 5, 19);
    CHECK(DO(72, fd, 1, 0) == 1, 20);
    CHECK(DO(72, fd, 2, 0) == 0, 21);
    CHECK(DO(72, fd, 1, 0) == 0, 22);
    CHECK(DO(5, fd, meta, 0) == 0 && *(word *)(meta+48) == 5, 23);
    word inode = *(word *)(meta+8);
    CHECK(call(332,-100,(word)"/work/build/nested/file",0,0x7ff,(word)meta,0) == 0, 24);
    CHECK(*(word *)(meta+40) == 5 && *(word *)(meta+32) == inode, 25);
    CHECK(DO(8, fd, 0, 0) == 0, 26);
    CHECK(DO(0, fd, immutable, 5) == -14, 27);
    CHECK(DO(8, fd, 0, 1) == 0, 28);
    long pages = call(9,0,8192,3,0x22,-1,0);
    CHECK(pages > 0, 68);
    CHECK(DO(10, pages+4096, 4096, 0) == 0, 69);
    CHECK(DO(0, fd, pages+4094, 5) == 2, 70);
    CHECK(DO(8, fd, 0, 1) == 2, 71);
    CHECK(DO(0, fd, output, 3) == 3 && output[0] == 'l' && output[2] == 'o', 72);
    CHECK(DO(11, pages, 8192, 0) == 0, 73);
    CHECK(DO(8, fd, 0, 0) == 0, 74);
    CHECK(DO(0, fd, output, 5) == 5, 29);
    CHECK(output[0] == 'h' && output[4] == 'o', 30);
    CHECK(DO(1, fd, 1, 5) == -14, 31);
    CHECK(DO(5, fd, 1, 0) == -14, 32);
    CHECK(DO(0, fd, 1, 0) == 0, 33);
    CHECK(DO(3, 1048639, 0, 0) == -9, 34);
    CHECK(DO(2, "/work/build/nested/file", 0301, 0600) == -17, 35);
    CHECK(call(262,fd,(word)"",(word)meta,0x1000,0,0) == 0, 36);
    CHECK(*(word *)(meta+8) == inode, 37);
    CHECK(DO(87, "/work/build/nested/file", 0, 0) == 0, 38);
    CHECK(DO(4, "/work/build/nested/file", meta, 0) == -2, 39);
    CHECK(DO(8, fd, 0, 0) == 0, 40);
    CHECK(DO(0, fd, output, 5) == 5 && output[0] == 'h', 41);
    long replacement = DO(2, "/work/build/nested/file", 0102, 0600);
    CHECK(replacement > fd, 42);
    CHECK(DO(1, replacement, "other", 5) == 5, 43);
    CHECK(DO(5, replacement, meta, 0) == 0 && *(word *)(meta+8) != inode, 44);
    CHECK(DO(3, fd, 0, 0) == 0 && DO(3, replacement, 0, 0) == 0, 45);
    // Exhaustion must not truncate or mutate a file before open fails.
    long fds[64];
    for (word i = 0; i < 64; ++i) {
        fds[i] = DO(2, "/work/build/nested/file", 2, 0);
        CHECK(fds[i] >= 3, 46);
    }
    CHECK(DO(2, "/work/build/nested/file", 01002, 0) == -24, 47);
    CHECK(DO(5, fds[0], meta, 0) == 0 && *(word *)(meta+48) == 5, 48);
    for (word i = 0; i < 64; ++i) CHECK(DO(3, fds[i], 0, 0) == 0, 49);
    fd = DO(2, "/out/product", 0102, 0644);
    CHECK(fd >= 3, 50);
    for (word i = 0; i < sizeof data; ++i) data[i] = i % 251;
    for (word i = 0; i < sizeof data; i += 4096) CHECK(DO(1, fd, data+i, 4096) == 4096, 51);
    CHECK(DO(1, fd, "x", 1) == 1, 52);
    CHECK(DO(8, fd, 0, 0) == 0, 53);
    for (word i = 0; i < sizeof output; i += 4096) CHECK(DO(0, fd, output+i, 4096) == 4096, 54);
    for (word i = 0; i < sizeof output; ++i) CHECK(output[i] == data[i], 55);
    CHECK(DO(0,fd,output,1)==1 && output[0]=='x',89);
    // Sparse growth and truncate/regrow must never reveal stale bytes.
    CHECK(DO(8,fd,2*1024*1024,0)==2*1024*1024 && DO(1,fd,"Q",1)==1,90);
    CHECK(DO(8,fd,2*1024*1024-1,0)==2*1024*1024-1,91);
    CHECK(DO(0,fd,output,2)==2 && output[0]==0 && output[1]=='Q',92);
    CHECK(DO(77,fd,3,0)==0 && DO(77,fd,8192,0)==0 && DO(8,fd,0,0)==0,93);
    CHECK(DO(0,fd,output,4096)==4096,94);
    CHECK(output[0]==data[0] && output[1]==data[1] && output[2]==data[2],95);
    for (word i=3;i<4096;++i) CHECK(output[i]==0,96);
    CHECK(DO(0,fd,output,4096)==4096,97);
    for (word i=0;i<4096;++i) CHECK(output[i]==0,98);
    CHECK(DO(91, fd, 0755, 0) == 0, 56);
    CHECK(DO(5, fd, meta, 0) == 0 && (*(unsigned int *)(meta+24) & 0777) == 0755, 57);
    CHECK(DO(3, fd, 0, 0) == 0, 58);
    CHECK(DO(87, "/out/product", 0, 0) == 0, 59);
    CHECK(DO(4, "/out/product", meta, 0) == -2, 60);
    DO(1, 1, "memory-storage: PASS\n", 21);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall storage_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
