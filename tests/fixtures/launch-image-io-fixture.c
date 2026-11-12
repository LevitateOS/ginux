/* Configured image I/O, virtual statfs, child-only virtual credentials,
   legacy stat/lstat as their newfstatat form, and the vectored and *at forms
   of image reads compared with their plain equivalents. */
typedef unsigned long word;
static long call(long n, word a, word b, word c, word d, word e, word f)
{
    register word r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
#define DO(n,a,b,c) call(n,(word)(a),(word)(b),(word)(c),0,0,0)
#define CHECK(condition,code) if (!(condition)) return code
static unsigned char buffer[2*1024*1024+32];
static word info[15];
static long system_view(int denied) {
    unsigned char view[128];
    for (unsigned i=0;i<sizeof view;++i) view[i]=0xa5;
    long result=DO(99,view+8,0,0);
    CHECK(result==(denied ? -1 : 0),50);
    for (unsigned i=0;i<sizeof view;++i)
        CHECK(view[i]==(!denied && i>=8 && i<120 ? 0 : 0xa5),51);
    return 0;
}
/* x86-64 stat(4) and lstat(6) are newfstatat(AT_FDCWD, path, buf, 0) and
   newfstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW), as musl issues them. */
#define AT ((word)-100)
#define NOFOLLOW 0x100
static unsigned char legacy[144] __attribute__((aligned(8)));
static unsigned char at[144] __attribute__((aligned(8)));
static unsigned mode_of(const unsigned char *st) { return *(const unsigned *)(st+24) & 0170000; }
static int same(long a, long b)
{
    if (a!=b) return 0;
    for (unsigned i=0;i<sizeof legacy;++i) if (legacy[i]!=at[i]) return 0;
    return 1;
}
static void fill(void)
{
    for (unsigned i=0;i<sizeof legacy;++i) { legacy[i]=0xa5; at[i]=0xa5; }
}
/* Both forms return the same result and the same bytes for this path. */
static int parity(const char *path)
{
    fill();
    long a=DO(4,path,legacy,0), b=call(262,AT,(word)path,(word)at,0,0,0);
    if (!same(a,b)) return 0;
    fill();
    a=DO(6,path,legacy,0); b=call(262,AT,(word)path,(word)at,NOFOLLOW,0,0);
    return same(a,b);
}
/* The kernel ABI preserves every argument register across a syscall. */
static int preserved(long n, const char *path)
{
    register word r10 __asm__("r10")=0x1010, r8 __asm__("r8")=0x0808, r9 __asm__("r9")=0x0909;
    word rdi=(word)path, rsi=(word)legacy, rdx=0x0d0d;
    long result=n;
    __asm__ volatile("syscall":"+a"(result),"+D"(rdi),"+S"(rsi),"+d"(rdx),"+r"(r10),"+r"(r8),"+r"(r9)::"rcx","r11","memory");
    return result==0 && rdi==(word)path && rsi==(word)legacy && rdx==0x0d0d
        && r10==0x1010 && r8==0x0808 && r9==0x0909;
}
static long legacy_stat(void)
{
    long fd=DO(2,"/work/file",0102,0600); CHECK(fd>=3 && DO(3,fd,0,0)==0,60);
    CHECK(DO(83,"/work/dir",0755,0)==0,61);
    CHECK(DO(88,"file","/work/link",0)==0 && DO(88,"missing","/work/dangling",0)==0,62);
    static const char *paths[]={
        "/image","/image-dir","/image-link","/image-dangling","image-link","/bin/../image",
        "/missing","/image/child","/work/file","/work/dir","/work/link","/work/dangling",
        "/work/missing","/dev/null","/dev","/dev/missing","/proc/self/maps",0};
    for (int i=0;paths[i];++i) CHECK(parity(paths[i]),63);
    /* stat follows a final symlink and lstat does not, in image and owned paths. */
    CHECK(DO(4,"/image-link",legacy,0)==0 && mode_of(legacy)==0100000,64);
    CHECK(DO(6,"/image-link",legacy,0)==0 && mode_of(legacy)==0120000,65);
    CHECK(DO(4,"/work/link",legacy,0)==0 && mode_of(legacy)==0100000,66);
    CHECK(DO(6,"/work/link",legacy,0)==0 && mode_of(legacy)==0120000,67);
    CHECK(DO(4,"/image-dir",legacy,0)==0 && mode_of(legacy)==0040000,68);
    CHECK(DO(6,"/work/dir",legacy,0)==0 && mode_of(legacy)==0040000,69);
    CHECK(DO(6,"/dev/null",legacy,0)==0 && mode_of(legacy)==0020000,70);
    CHECK(DO(4,"/image-dangling",legacy,0)==-2 && DO(6,"/image-dangling",legacy,0)==0,71);
    CHECK(DO(4,"/work/dangling",legacy,0)==-2 && DO(6,"/work/dangling",legacy,0)==0,72);
    /* Missing paths and non-directory components. */
    CHECK(DO(4,"/missing",legacy,0)==-2 && DO(6,"/missing",legacy,0)==-2,73);
    CHECK(DO(4,"/work/missing",legacy,0)==-2 && DO(6,"/dev/missing",legacy,0)==-2,74);
    CHECK(DO(4,"/image/child",legacy,0)==-20 && DO(6,"/image/child",legacy,0)==-20,75);
    CHECK(DO(4,"",legacy,0)==-2 && DO(6,"",legacy,0)==-2,76);
    /* Faulting path and buffer addresses, as newfstatat reports them. */
    for (int n=4;n<=6;n+=2) {
        CHECK(DO(n,0,legacy,0)==-14 && DO(n,1,legacy,0)==-14,77);
        CHECK(call(262,AT,1,(word)at,n==6?NOFOLLOW:0,0,0)==-14,78);
        static const char *targets[]={"/image","/image-dir","/work/file","/dev/null","/proc/self/maps",0};
        for (int i=0;targets[i];++i) {
            CHECK(DO(n,targets[i],1,0)==-14,79);
            CHECK(call(262,AT,(word)targets[i],1,n==6?NOFOLLOW:0,0,0)==-14,80);
        }
        /* Registers return unchanged whichever backend answers. */
        CHECK(preserved(n,"/image") && preserved(n,"/image-link") && preserved(n,"/work/file"),81);
        CHECK(preserved(n,"/dev/null") && preserved(n,"/proc/self/maps"),82);
    }
    /* The image stays read-only. */
    CHECK(DO(87,"/image",0,0)<0 && DO(2,"/image",1,0)<0,83);
    DO(1,1,"legacy-stat: PASS\n",18);
    return 0;
}
/* The contract decides each legacy call by its own operation. */
static long legacy_stat_policy(void)
{
    CHECK(DO(6,"/image",legacy,0)==-1 && DO(6,"/work",legacy,0)==-1,90);
    CHECK(DO(4,"/image",legacy,0)==0 && call(262,AT,(word)"/image",(word)at,NOFOLLOW,0,0)==0,91);
    DO(1,1,"legacy-stat-policy: PASS\n",25);
    return 0;
}
/* readv as musl stdio issues it, preadv-free: every result and every byte
   must equal the plain read or pread of the same range. */
struct iov { void *base; word len; };
#define TEXT 5120
static unsigned char text[TEXT], one[8], wide[1024], spare[2048];
static long position(long fd) { return DO(8,fd,0,1); }
static int bytes_equal(const unsigned char *a, const unsigned char *b, word n)
{
    for (word i=0;i<n;++i) if (a[i]!=b[i]) return 0;
    return 1;
}
static void clear(void)
{
    for (unsigned i=0;i<sizeof one;++i) one[i]=0xa5;
    for (unsigned i=0;i<sizeof wide;++i) wide[i]=0xa5;
    for (unsigned i=0;i<sizeof spare;++i) spare[i]=0xa5;
}
/* readv of {first, second} bytes at offset equals pread of the same range. */
static int vector_parity(long fd, word offset, word first, word second)
{
    clear();
    if (DO(8,fd,offset,0)!=(long)offset) return 0;
    struct iov v[2]={{one,first},{wide,second}};
    long got=DO(19,fd,v,2);
    long want=call(17,fd,(word)spare,first+second,offset,0,0);
    if (got!=want || got<0) return 0;
    if (position(fd)!=(long)offset+got) return 0;
    word head=(word)got<first ? (word)got : first;
    return bytes_equal(one,text+offset,head) && bytes_equal(wide,text+offset+head,got-head)
        && bytes_equal(one,spare,head) && bytes_equal(wide,spare+head,got-head);
}
/* The kernel ABI preserves every argument register across readv. */
static int vector_preserved(long fd, struct iov *v)
{
    register word r10 __asm__("r10")=0x1010, r8 __asm__("r8")=0x0808, r9 __asm__("r9")=0x0909;
    word rdi=fd, rsi=(word)v, rdx=1;
    long result=19;
    __asm__ volatile("syscall":"+a"(result),"+D"(rdi),"+S"(rsi),"+d"(rdx),"+r"(r10),"+r"(r8),"+r"(r9)::"rcx","r11","memory");
    return result>=0 && rdi==(word)fd && rsi==(word)v && rdx==1
        && r10==0x1010 && r8==0x0808 && r9==0x0909;
}
static int vectored_file(long fd)
{
    /* musl's {1, N} and {0, N} shapes, mid-file, near and at end of file. */
    static const word offsets[]={0,1,4095,4096,TEXT-1025,TEXT-10,TEXT-1,TEXT,TEXT+7};
    for (unsigned i=0;i<sizeof offsets/sizeof *offsets;++i) {
        if (!vector_parity(fd,offsets[i],1,1024) || !vector_parity(fd,offsets[i],0,1024)) return 0;
        if (!vector_parity(fd,offsets[i],8,0) || !vector_parity(fd,offsets[i],0,0)) return 0;
    }
    /* Consecutive calls advance one shared offset, as read does. */
    struct iov v[3]={{one,3},{wide,0},{spare,5}};
    if (DO(8,fd,0,0)!=0 || DO(19,fd,v,3)!=8 || position(fd)!=8) return 0;
    if (!bytes_equal(one,text,3) || !bytes_equal(spare,text+3,5)) return 0;
    if (DO(19,fd,v,3)!=8 || !bytes_equal(one,text+8,3) || position(fd)!=16) return 0;
    if (DO(0,fd,wide,4)!=4 || !bytes_equal(wide,text+16,4) || position(fd)!=20) return 0;
    /* No vectors, a short array and an empty first vector. */
    if (DO(19,fd,v,0)!=0 || position(fd)!=20) return 0;
    if (DO(19,fd,v,1)!=3 || position(fd)!=23) return 0;
    /* Linux rejects an over-long array, a negative length and faulting
       arrays and buffers the same way it rejects them for read. */
    if (DO(19,fd,v,1025)!=-22 || position(fd)!=23) return 0;
    struct iov negative[1]={{wide,(word)1<<63}};
    if (DO(19,fd,negative,1)!=-22 || position(fd)!=23) return 0;
    if (DO(19,fd,1,1)!=-14 || DO(19,fd,0,2)!=-14) return 0;
    struct iov unmapped[1]={{(void *)1,16}};
    if (DO(19,fd,unmapped,1)!=-14 || DO(0,fd,1,16)!=-14 || position(fd)!=23) return 0;
    /* A fault after the first vector is a short read of the first. */
    struct iov partial[2]={{one,4},{(void *)1,16}};
    if (DO(19,fd,partial,2)!=4 || !bytes_equal(one,text+23,4) || position(fd)!=27) return 0;
    /* A zero-length vector is never touched. */
    struct iov hole[2]={{(void *)1,0},{wide,4}};
    if (DO(19,fd,hole,2)!=4 || !bytes_equal(wide,text+27,4)) return 0;
    return vector_preserved(fd,v);
}
static long vectored(void)
{
    /* The same bytes in an image file and in owned storage. */
    for (int i=0;i<TEXT;++i) text[i]=(unsigned char)(i*7+i/256);
    long fd=DO(2,"/image-text",0,0); CHECK(fd>=3,100);
    CHECK(DO(0,fd,buffer,TEXT+1)==TEXT && bytes_equal(buffer,text,TEXT),101);
    long owned=DO(2,"/work/text",0102,0600); CHECK(owned>=3,102);
    CHECK(DO(1,owned,text,TEXT)==TEXT,103);
    CHECK(vectored_file(fd),104);
    CHECK(vectored_file(owned),105);
    /* The image read bound applies to the sum of the vectors, as to read. */
    struct iov bound[2]={{buffer,1},{buffer+1,64*1024*1024-1}};
    CHECK(DO(8,fd,0,0)==0 && DO(19,fd,bound,2)==TEXT && DO(0,fd,buffer,1)==0,106);
    bound[1].len=64*1024*1024;
    CHECK(DO(19,fd,bound,2)==-1 && DO(0,fd,buffer,64*1024*1024+1)==-1,107);
    long large=DO(2,"/image",0,0); CHECK(large>=3,108);
    struct iov whole[2]={{buffer,1},{buffer+1,sizeof buffer-1}};
    CHECK(DO(19,large,whole,2)==(long)sizeof buffer && buffer[0]=='Q' && buffer[sizeof buffer-1]=='Q',109);
    CHECK(DO(3,large,0,0)==0,110);
    /* Directories, metadata-only references and closed numbers. */
    long dir=DO(2,"/image-dir",0200000,0); CHECK(dir>=3,111);
    struct iov v[2]={{one,1},{wide,sizeof wide}};
    CHECK(DO(19,dir,v,2)==-21 && DO(0,dir,wide,1)==-21,112);
    long path=DO(2,"/image-text",010000000,0); CHECK(path>=3,113);
    CHECK(DO(19,path,v,2)==-9 && DO(0,path,wide,1)==-9,114);
    CHECK(DO(19,12345,v,2)==-9 && DO(19,-1,v,2)==-9,115);
    CHECK(DO(3,path,0,0)==0 && DO(19,path,v,2)==-9,116);
    /* Image descriptors stay unwritable, vectored or not. */
    CHECK(DO(8,fd,9,0)==9 && DO(20,fd,v,2)==-9 && DO(1,fd,"x",1)==-9 && position(fd)==9,124);
    /* The inherited console reads with readv as with read. */
    clear();
    CHECK(DO(19,0,v,2)==8 && one[0]=='c' && bytes_equal(wide,(const unsigned char *)"onsole\n",7),125);
    /* A private read-only mapping of an image file holds its bytes, a
       private writable one never reaches the file, a shared writable one is
       refused for a read-only descriptor. */
    long map=call(9,0,8192,1,2,fd,4096);
    CHECK(map>0 && bytes_equal((unsigned char *)map,text+4096,TEXT-4096),117);
    CHECK(((unsigned char *)map)[TEXT-4096]==0 && DO(11,map,8192,0)==0,118);
    map=call(9,0,4096,3,2,fd,0);
    CHECK(map>0 && bytes_equal((unsigned char *)map,text,4096),119);
    ((unsigned char *)map)[0]^=0xff;
    CHECK(call(17,fd,(word)wide,1,0,0,0)==1 && wide[0]==text[0] && DO(11,map,4096,0)==0,120);
    CHECK(call(9,0,4096,3,1,fd,0)==-13,121);
    CHECK(DO(3,fd,0,0)==0 && DO(3,dir,0,0)==0 && DO(3,owned,0,0)==0,122);
    CHECK(DO(87,"/work/text",0,0)==0,123);
    DO(1,1,"vectored: PASS\n",15);
    return 0;
}
/* faccessat and readlinkat answer exactly as access and readlink do. */
static char link_a[64], link_b[64];
static int access_parity(const char *path, word mode)
{
    return DO(21,path,mode,0)==DO(269,AT,path,mode);
}
static int link_parity(const char *path, word size)
{
    for (unsigned i=0;i<sizeof link_a;++i) { link_a[i]=0x5a; link_b[i]=0x5a; }
    long a=DO(89,path,link_a,size), b=call(267,AT,(word)path,(word)link_b,size,0,0);
    if (a!=b) return 0;
    for (unsigned i=0;i<sizeof link_a;++i) if (link_a[i]!=link_b[i]) return 0;
    return 1;
}
static long metadata_at(void)
{
    long fd=DO(2,"/work/file",0102,0600); CHECK(fd>=3 && DO(3,fd,0,0)==0,130);
    CHECK(DO(83,"/work/dir",0755,0)==0,131);
    CHECK(DO(88,"file","/work/link",0)==0 && DO(88,"missing","/work/dangling",0)==0,132);
    long image=DO(2,"/image-text",0,0); CHECK(image>=3,133);
    static char self[32]="/proc/self/fd/";
    self[14]=(char)('0'+image/10); self[15]=(char)('0'+image%10); self[16]=0;
    if (image<10) { self[14]=(char)('0'+image); self[15]=0; }
    static const char *paths[]={
        "/image","/image-dir","/image-dir/inner","/image-link","/image-dangling","image-link",
        "/bin/../image-link","/image-dir/../image","/missing","/image/child","/image-link/child",
        "/work/file","/work/dir","/work/link","/work/dangling","/work/missing","/dev/null","/dev",
        "/dev/missing","/proc/self/maps","/proc/self/exe","/proc","/proc/1/root","/sys",self,0};
    for (int i=0;paths[i];++i) {
        for (word mode=0;mode<=8;++mode) CHECK(access_parity(paths[i],mode),134);
        CHECK(link_parity(paths[i],sizeof link_a),135);
        CHECK(link_parity(paths[i],2),136);
        CHECK(link_parity(paths[i],0),137);
        CHECK(call(267,AT,(word)paths[i],1,sizeof link_a,0,0)==DO(89,paths[i],1,sizeof link_a),138);
    }
    CHECK(DO(21,"",4,0)==-2 && DO(269,AT,"",4)==-2,139);
    CHECK(DO(89,"",link_a,8)==-2 && call(267,AT,(word)"",(word)link_a,8,0,0)==-2,140);
    CHECK(DO(21,1,4,0)==-14 && DO(269,AT,1,4)==-14,141);
    CHECK(DO(89,1,link_a,8)==-14 && call(267,AT,1,(word)link_a,8,0,0)==-14,142);
    /* Read results themselves. */
    CHECK(call(267,AT,(word)"/image-link",(word)link_b,64,0,0)==5 && bytes_equal((unsigned char *)link_b,(const unsigned char *)"image",5),143);
    CHECK(call(267,AT,(word)"/image-dangling",(word)link_b,64,0,0)==7 && bytes_equal((unsigned char *)link_b,(const unsigned char *)"missing",7),144);
    CHECK(call(267,AT,(word)"/dev/null",(word)link_b,64,0,0)==-22 && call(267,AT,(word)"/dev",(word)link_b,64,0,0)==-22,145);
    CHECK(DO(269,AT,"/image-text",4)==0 && DO(269,AT,"/image-dangling",0)==-2 && DO(269,AT,"/image",8)==-22,146);
    /* Relative to an image directory, to the image root and to owned storage. */
    long dir=DO(2,"/image-dir",0200000,0); CHECK(dir>=3,147);
    long root=DO(2,"/",0200000,0); CHECK(root>=3,148);
    long work=DO(2,"/work",0200000,0); CHECK(work>=3,149);
    CHECK(DO(269,dir,"inner",4)==DO(21,"/image-dir/inner",4,0) && DO(269,dir,"inner",4)==0,150);
    CHECK(DO(269,dir,"missing",0)==-2 && DO(269,dir,"../image",4)==0,151);
    CHECK(call(267,root,(word)"image-link",(word)link_b,64,0,0)==5,152);
    CHECK(call(267,dir,(word)"../image-link",(word)link_b,64,0,0)==5,153);
    CHECK(call(267,dir,(word)"inner",(word)link_b,64,0,0)==-22,154);
    CHECK(call(267,work,(word)"link",(word)link_b,64,0,0)==4,155);
    CHECK(call(267,work,(word)"../image-link",(word)link_b,64,0,0)==5,156);
    CHECK(DO(269,work,"../image-text",4)==0 && DO(269,work,"file",4)==0,157);
    /* A file descriptor is not a directory; a bad descriptor is EBADF. */
    CHECK(DO(269,image,"x",0)==-20 && call(267,image,(word)"x",(word)link_b,64,0,0)==-20,158);
    CHECK(DO(269,12345,"x",0)==-9 && call(267,12345,(word)"x",(word)link_b,64,0,0)==-9,159);
    /* Absolute paths ignore the directory argument, as Linux does. */
    CHECK(DO(269,12345,"/image-text",4)==0 && call(267,12345,(word)"/image-link",(word)link_b,64,0,0)==5,160);
    CHECK(DO(3,dir,0,0)==0 && DO(3,root,0,0)==0 && DO(3,work,0,0)==0 && DO(3,image,0,0)==0,161);
    /* The image stays unchanged and read-only. */
    CHECK(DO(87,"/image-link",0,0)<0 && DO(2,"/image-text",1,0)<0,162);
    DO(1,1,"metadata-at: PASS\n",18);
    return 0;
}
/* The contract decides each form by its own operation. */
static long vectored_policy(void)
{
    long fd=DO(2,"/image-text",0,0); CHECK(fd>=3,170);
    struct iov v[2]={{one,1},{wide,sizeof wide}};
    CHECK(DO(19,fd,v,2)==-1 && DO(0,fd,wide,4)==4,171);
    CHECK(DO(269,AT,"/image-text",4)==-1 && DO(21,"/image-text",4,0)==0,172);
    CHECK(call(267,AT,(word)"/image-link",(word)link_b,64,0,0)==-1 && DO(89,"/image-link",link_b,64)==5,173);
    DO(1,1,"vectored-policy: PASS\n",22);
    return 0;
}
long image_io_main(word *stack)
{
    char scenario=stack[0]>1 ? ((char *)stack[2])[0] : 0;
    if (scenario=='L') return legacy_stat();
    if (scenario=='P') return legacy_stat_policy();
    if (scenario=='V') return vectored();
    if (scenario=='A') return metadata_at();
    if (scenario=='Q') return vectored_policy();
    int denied=stack[0]>1 && ((char *)stack[2])[0]=='D';
    long system_result=system_view(denied);
    if (system_result) return system_result;
    if (stack[0]>1 && (denied || ((char *)stack[2])[0]=='S')) return 0;
    if(stack[0]>1) {
        CHECK(DO(102,0,0,0)==12345 && DO(107,0,0,0)==12345,30);
        CHECK(DO(104,0,0,0)==23456 && DO(108,0,0,0)==23456,31);
        CHECK(DO(105,0,0,0)==-1 && DO(106,0,0,0)==-1,32);
        CHECK(DO(1,1,"drop-ready\n",11)==11,33);
        CHECK(DO(0,0,buffer,1)==1 && buffer[0]=='G',34);
        return 0;
    }
    long fd=DO(2,"/image",0,0); CHECK(fd>=3,1);
    /* Pointer arguments must not be mistaken for internal network handles,
       including a 64-bit address whose low word aliases the handle range. */
    for (word address=0x60000000; address<=0x160000000; address+=0x100000000) {
        CHECK(call(9,address,4096,3,0x100022,-1,0)==(long)address,40);
        CHECK(DO(10,address,4096,1)==0,41);
        CHECK(DO(11,address,4096,0)==0,42);
        CHECK(call(9,address,4096,1,0x100002,fd,0)==(long)address,43);
        CHECK(*(unsigned char *)address=='Q',44);
        CHECK(DO(11,address,4096,0)==0,45);
    }
    CHECK(DO(0,fd,buffer,2*1024*1024)==2*1024*1024,2);
    CHECK(buffer[0]=='Q' && buffer[2*1024*1024-1]=='Q',3);
    CHECK(call(17,fd,(word)buffer,2*1024*1024,16,0,0)==2*1024*1024,4);
    CHECK(buffer[0]=='Q' && buffer[2*1024*1024-1]=='Q',5);
    CHECK(DO(137,"/image",info,0)==0 && info[0]==0x01021994 && info[10]==1,6);
    CHECK(DO(138,fd,info,0)==0 && info[10]==1 && info[7]==0,7);
    CHECK(DO(137,"/missing",info,0)==-2,8);
    CHECK(DO(137,"/image",1,0)==-14 && DO(138,fd,1,0)==-14,9);
    CHECK(DO(138,12345,info,0)==-9,10);
    CHECK(DO(137,"/work",info,0)==0 && info[10]==0 && info[2]>0,11);
    long owned=DO(2,"/work/file",0102,0600); CHECK(owned>=3,12);
    CHECK(DO(138,owned,info,0)==0 && info[10]==0 && info[7]==0,13);
    CHECK(DO(3,owned,0,0)==0 && DO(3,fd,0,0)==0,14);
    long child=DO(57,0,0,0); CHECK(child>=0,15);
    if(!child) {
        CHECK(DO(116,33,0,0)==-22 && DO(116,1,1,0)==-14,16);
        CHECK(DO(116,0,0,0)==0,17);
        CHECK(DO(106,23456,0,0)==0 && DO(105,12345,0,0)==0,18);
        CHECK(DO(116,0,0,0)==-1,19);
        char *argv[]={"/bin/fixture","after-drop",0}, *env[]={0};
        DO(59,argv[0],argv,env); return 20;
    }
    int status=-1; CHECK(DO(61,child,&status,0)==child && status==0,21);
    CHECK(DO(102,0,0,0)==0 && DO(104,0,0,0)==0,22);
    DO(1,1,"image-io: PASS\n",15);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall image_io_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
