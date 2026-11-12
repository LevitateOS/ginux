/* Configured image I/O, virtual statfs, child-only virtual credentials,
   legacy stat/lstat as their newfstatat form, the vectored and *at forms
   of image reads compared with their plain equivalents, readahead and
   fadvise64, sendfile and copy_file_range, and the xattr calls of a
   filesystem without attributes. */
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
/* preadv and preadv2 answer as pread64 and readv; readahead and fadvise64
   answer as Linux does, with no effect. */
static long preadv_at(long fd, struct iov *v, long n, long offset)
{
    return call(295,fd,(word)v,n,offset,0,0);
}
static long preadv2_at(long fd, struct iov *v, long n, long offset, long flags)
{
    return call(327,fd,(word)v,n,offset,0,flags);
}
/* preadv (or preadv2) of {first, second} at offset equals pread64 of the
   same range and leaves the shared offset where it was. */
static int positional_parity(long fd, word offset, word first, word second, int two)
{
    clear();
    if (DO(8,fd,77,0)!=77) return 0;
    struct iov v[2]={{one,first},{wide,second}};
    long got=two ? preadv2_at(fd,v,2,offset,0) : preadv_at(fd,v,2,offset);
    long want=call(17,fd,(word)spare,first+second,offset,0,0);
    if (got!=want || got<0 || position(fd)!=77) return 0;
    word head=(word)got<first ? (word)got : first;
    return bytes_equal(one,text+offset,head) && bytes_equal(wide,text+offset+head,got-head)
        && bytes_equal(one,spare,head) && bytes_equal(wide,spare+head,got-head);
}
/* preadv2 at offset -1 is readv at the shared offset, which it advances. */
static int current_parity(long fd, word offset, word first, word second)
{
    clear();
    if (DO(8,fd,offset,0)!=(long)offset) return 0;
    struct iov v[2]={{one,first},{wide,second}};
    long got=preadv2_at(fd,v,2,-1,0);
    long want=call(17,fd,(word)spare,first+second,offset,0,0);
    if (got!=want || got<0 || position(fd)!=(long)offset+got) return 0;
    word head=(word)got<first ? (word)got : first;
    return bytes_equal(one,text+offset,head) && bytes_equal(wide,text+offset+head,got-head);
}
/* The kernel ABI preserves every argument register across preadv2. */
static int preadv2_preserved(long fd, struct iov *v)
{
    register word r10 __asm__("r10")=16, r8 __asm__("r8")=0x0808, r9 __asm__("r9")=0;
    word rdi=fd, rsi=(word)v, rdx=1;
    long result=327;
    __asm__ volatile("syscall":"+a"(result),"+D"(rdi),"+S"(rsi),"+d"(rdx),"+r"(r10),"+r"(r8),"+r"(r9)::"rcx","r11","memory");
    return result>=0 && rdi==(word)fd && rsi==(word)v && rdx==1 && r10==16 && r8==0x0808 && r9==0;
}
static int positional_file(long fd)
{
    static const word offsets[]={0,1,4095,4096,TEXT-1025,TEXT-10,TEXT-1,TEXT,TEXT+7};
    for (unsigned i=0;i<sizeof offsets/sizeof *offsets;++i) {
        for (int two=0;two<2;++two)
            if (!positional_parity(fd,offsets[i],1,1024,two) || !positional_parity(fd,offsets[i],0,1024,two)
                || !positional_parity(fd,offsets[i],8,0,two)) return 0;
        if (!current_parity(fd,offsets[i],1,1024) || !current_parity(fd,offsets[i],0,0)) return 0;
    }
    struct iov v[2]={{one,4},{wide,4}};
    /* Linux checks the offset before the descriptor and the flags after it. */
    if (preadv_at(fd,v,2,-5)!=-22 || preadv_at(12345,v,2,-5)!=-22) return 0;
    if (preadv2_at(fd,v,2,-2,0)!=-22 || preadv2_at(12345,v,2,-2,8)!=-22) return 0;
    if (preadv_at(12345,v,2,0)!=-9 || preadv2_at(12345,v,2,0,8)!=-9 || preadv2_at(-1,v,2,-1,0)!=-9) return 0;
    if (DO(8,fd,5,0)!=5) return 0;
    for (long flags=1;flags<=0x100;flags<<=1)
        if (preadv2_at(fd,v,2,0,flags)!=-95 || preadv2_at(fd,v,2,-1,flags)!=-95) return 0;
    if (position(fd)!=5) return 0;
    /* The array is checked as readv checks it. */
    if (preadv_at(fd,v,1025,0)!=-22 || preadv_at(fd,(struct iov *)1,1,0)!=-14) return 0;
    struct iov unmapped[1]={{(void *)1,16}};
    if (preadv_at(fd,unmapped,1,0)!=-14 || preadv2_at(fd,unmapped,1,-1,0)!=-14 || position(fd)!=5) return 0;
    if (preadv_at(fd,v,0,0)!=0 || preadv2_at(fd,v,0,-1,0)!=0 || position(fd)!=5) return 0;
    return preadv2_preserved(fd,v) && position(fd)==5;
}
static long advice(long fd, word advice_value) { return call(221,fd,0,0,advice_value,0,0); }
static long readahead(long fd) { return DO(187,fd,0,4096); }
static long vectored_at(void)
{
    for (int i=0;i<TEXT;++i) text[i]=(unsigned char)(i*7+i/256);
    long fd=DO(2,"/image-text",0,0); CHECK(fd>=3,200);
    long owned=DO(2,"/work/text",0102,0600); CHECK(owned>=3,201);
    CHECK(DO(1,owned,text,TEXT)==TEXT,202);
    long dir=DO(2,"/image-dir",0200000,0); CHECK(dir>=3,207);
    long owned_dir=DO(2,"/work",0200000,0); CHECK(owned_dir>=3,208);
    long path=DO(2,"/image-text",010000000,0); CHECK(path>=3,212);
    int pipe[2]; CHECK(DO(22,pipe,0,0)==0,214);
    long null=DO(2,"/dev/null",2,0); CHECK(null>=3,218);
    long wronly=DO(2,"/work/wronly",0101,0600); CHECK(wronly>=3,221);
    int pair[2]; CHECK(call(53,1,1,0,(word)pair,0,0)==0,222);
    long counter=DO(290,0,0,0); CHECK(counter>=3,223);
    long null_out=DO(2,"/dev/null",1,0); CHECK(null_out>=3,224);
    /* readahead: a readable regular file only, with no read. */
    CHECK(DO(8,fd,9,0)==9 && readahead(fd)==0 && call(187,fd,(word)-5,(word)-1,0,0,0)==0 && position(fd)==9,225);
    CHECK(readahead(owned)==0 && readahead(wronly)==-9,226);
    CHECK(readahead(dir)==-22 && readahead(owned_dir)==-22 && readahead(pipe[0])==-22,227);
    CHECK(readahead(pipe[1])==-9 && readahead(pair[0])==-22 && readahead(counter)==-22,228);
    CHECK(readahead(null)==-22 && readahead(null_out)==-9 && readahead(path)==-9,229);
    CHECK(readahead(12345)==-9 && readahead(-1)==-9 && readahead(0)==-22 && readahead(1)==-9,230);
    /* fadvise64: any advice 0..5 on anything but a pipe, with no effect. */
    for (word a=0;a<=5;++a) {
        CHECK(advice(fd,a)==0 && advice(owned,a)==0 && advice(wronly,a)==0,231);
        CHECK(advice(dir,a)==0 && advice(owned_dir,a)==0 && advice(pair[0],a)==0,232);
        CHECK(advice(counter,a)==0 && advice(null,a)==0 && advice(pipe[0],a)==-29,233);
    }
    CHECK(advice(fd,6)==-22 && advice(fd,(word)-1)==-22 && advice(pipe[0],6)==-29,234);
    CHECK(call(221,fd,0,(word)-1,0,0,0)==-22 && call(221,fd,(word)-5,10,0,0,0)==0,235);
    CHECK(call(221,fd,0,0,((word)1<<32)|4,0,0)==0,236);
    CHECK(advice(path,0)==-9 && advice(12345,0)==-9 && advice(0,0)==-29,237);
    CHECK(position(fd)==9 && call(17,fd,(word)wide,16,0,0,0)==16 && bytes_equal(wide,text,16),238);
    /* preadv and preadv2 against pread64 and readv. */
    CHECK(positional_file(fd),203);
    CHECK(positional_file(owned),204);
    /* The image read bound applies to the sum, as to readv. */
    struct iov bound[2]={{buffer,1},{buffer+1,64*1024*1024-1}};
    CHECK(preadv_at(fd,bound,2,0)==TEXT && preadv2_at(fd,bound,2,0,0)==TEXT,205);
    bound[1].len=64*1024*1024;
    CHECK(preadv_at(fd,bound,2,0)==-1 && DO(19,fd,bound,2)==-1,206);
    struct iov v[2]={{one,1},{wide,sizeof wide}};
    /* Directories, references, pipes, devices and the console answer as
       pread64 and readv do. */
    CHECK(preadv_at(dir,v,2,0)==call(17,dir,(word)wide,8,0,0,0) && preadv_at(dir,v,2,0)<0,209);
    CHECK(preadv_at(owned_dir,v,2,0)==call(17,owned_dir,(word)wide,8,0,0,0) && preadv_at(owned_dir,v,2,0)<0,210);
    CHECK(preadv2_at(dir,v,2,-1,0)==DO(19,dir,v,2),211);
    CHECK(preadv_at(path,v,2,0)==-9 && preadv2_at(path,v,2,-1,0)==-9 && preadv2_at(path,v,2,0,8)==-9,213);
    CHECK(preadv_at(pipe[0],v,2,0)==-29 && call(17,pipe[0],(word)wide,1,0,0,0)==-29,215);
    CHECK(DO(1,pipe[1],"abc",3)==3 && preadv2_at(pipe[0],v,2,-1,0)==3 && one[0]=='a' && wide[0]=='b',216);
    CHECK(preadv_at(pipe[1],v,2,0)==-29,217);
    CHECK(preadv_at(null,v,2,0)==0 && preadv2_at(null,v,2,-1,0)==0 && preadv_at(null,v,2,-5)==-22,219);
    CHECK(preadv_at(0,v,2,0)==call(17,0,(word)wide,1,0,0,0) && preadv_at(0,v,2,0)==-29,220);
    long closes[]={fd,owned,dir,owned_dir,path,pipe[0],pipe[1],null,wronly,pair[0],pair[1],counter,null_out};
    for (unsigned i=0;i<sizeof closes/sizeof *closes;++i) CHECK(DO(3,closes[i],0,0)==0,239);
    CHECK(DO(87,"/work/text",0,0)==0 && DO(87,"/work/wronly",0,0)==0,240);
    DO(1,1,"vectored-at: PASS\n",18);
    return 0;
}
/* sendfile and copy_file_range move what pread64 reads and write would
   write, a bounded chunk per call. */
static long sendfile_call(long out, long in, long *offset, word count)
{
    return call(40,out,in,(word)offset,count,0,0);
}
static long copy_range(long in, long *from, long out, long *to, word count, word flags)
{
    return call(326,in,(word)from,out,(word)to,count,flags);
}
static unsigned char moved[4096];
/* The owned file holds text[from, from+count) at `at`. */
static int holds(long fd, word at, word from, word count)
{
    for (unsigned i=0;i<sizeof moved;++i) moved[i]=0xa5;
    return call(17,fd,(word)moved,count,at,0,0)==(long)count && bytes_equal(moved,text+from,count);
}
static const long read_only_offset=1000;
static long transfers(void)
{
    for (int i=0;i<TEXT;++i) text[i]=(unsigned char)(i*7+i/256);
    long image=DO(2,"/image-text",0,0); CHECK(image>=3,300);
    long out=DO(2,"/work/out",0102,0600); CHECK(out>=3,301);
    /* Current offsets: both advance by the bytes moved. */
    CHECK(sendfile_call(out,image,0,1000)==1000 && position(image)==1000 && position(out)==1000,302);
    CHECK(holds(out,0,0,1000),303);
    /* An explicit offset is read, advanced and stored; the input's own
       offset stays. */
    long offset=2000;
    CHECK(sendfile_call(out,image,&offset,500)==500 && offset==2500 && position(image)==1000,304);
    CHECK(position(out)==1500 && holds(out,1000,2000,500),305);
    offset=TEXT-3;
    CHECK(sendfile_call(out,image,&offset,10)==3 && offset==TEXT,306);
    CHECK(sendfile_call(out,image,&offset,10)==0 && offset==TEXT,307);
    CHECK(sendfile_call(out,image,0,0)==0 && position(image)==1000,308);
    /* Owned to owned, and into a device at the device's write bound. */
    long copy=DO(2,"/work/copy",0102,0600); CHECK(copy>=3,309);
    offset=0;
    CHECK(sendfile_call(copy,out,&offset,1500)==1500 && offset==1500 && holds(copy,0,0,1000),310);
    CHECK(holds(copy,1000,2000,500) && position(out)==1503,311);
    long null=DO(2,"/dev/null",1,0); CHECK(null>=3,312);
    offset=0;
    CHECK(sendfile_call(null,image,&offset,TEXT)==4096 && offset==4096,313);
    /* Into the console. */
    long ascii=DO(2,"/image-ascii",0,0); CHECK(ascii>=3,314);
    CHECK(sendfile_call(1,ascii,0,64)==17 && position(ascii)==17,315);
    /* Each call moves at most 1 MiB. */
    long large=DO(2,"/image",0,0); CHECK(large>=3,316);
    long whole=DO(2,"/work/whole",0102,0600); CHECK(whole>=3,317);
    CHECK(sendfile_call(whole,large,0,3*1024*1024)==1024*1024 && position(large)==1024*1024,318);
    CHECK(sendfile_call(whole,large,0,3*1024*1024)==1024*1024,319);
    CHECK(sendfile_call(whole,large,0,3*1024*1024)==32 && sendfile_call(whole,large,0,1)==0,320);
    CHECK(call(17,whole,(word)moved,8,2*1024*1024+24,0,0)==8 && moved[0]=='Q' && moved[7]=='Q',321);
    /* Refusals, in Linux's order, consume nothing. */
    int pipe[2]; CHECK(DO(22,pipe,0,0)==0,322);
    int pair[2]; CHECK(call(53,1,1,0,(word)pair,0,0)==0,323);
    long dir=DO(2,"/image-dir",0200000,0); CHECK(dir>=3,324);
    long append=DO(2,"/work/append",02102,0600); CHECK(append>=3,325);
    long wronly=DO(2,"/work/wronly",0101,0600); CHECK(wronly>=3,326);
    long path=DO(2,"/image-text",010000000,0); CHECK(path>=3,327);
    CHECK(sendfile_call(out,pipe[0],0,10)==-22 && sendfile_call(out,dir,0,10)==-22,328);
    offset=0;
    CHECK(sendfile_call(out,pipe[0],&offset,10)==-29 && offset==0,329);
    CHECK(sendfile_call(pipe[1],image,0,10)==-22 && sendfile_call(pair[0],image,0,10)==-22,330);
    CHECK(sendfile_call(append,image,0,10)==-22 && position(image)==1000,331);
    CHECK(sendfile_call(image,image,0,10)==-9 && sendfile_call(out,wronly,0,10)==-9,332);
    CHECK(sendfile_call(out,image,(long *)1,10)==-14 && sendfile_call(12345,image,(long *)1,10)==-14,333);
    CHECK(sendfile_call(12345,image,0,10)==-9 && sendfile_call(out,12345,0,10)==-9,334);
    CHECK(sendfile_call(out,path,0,10)==-9 && sendfile_call(path,image,0,10)==-9,335);
    offset=-1;
    CHECK(sendfile_call(out,image,&offset,10)==-22 && offset==-1,336);
    offset=0;
    CHECK(sendfile_call(out,image,&offset,(word)-1)==-22 && offset==0,337);
    CHECK(position(image)==1000 && position(out)==1503,338);
    /* The offset is stored back whatever happened; a read-only one is
       EFAULT after the bytes have moved, as Linux does. */
    CHECK(sendfile_call(out,image,(long *)&read_only_offset,10)==-14 && position(out)==1513,339);
    CHECK(holds(out,1503,1000,10),340);
    /* copy_file_range: current offsets advance, explicit ones are stored. */
    long target=DO(2,"/work/target",0102,0600); CHECK(target>=3,341);
    CHECK(DO(8,image,0,0)==0,342);
    CHECK(copy_range(image,0,target,0,1000,0)==1000 && position(image)==1000 && position(target)==1000,343);
    CHECK(holds(target,0,0,1000),344);
    long from=3000, to=10;
    CHECK(copy_range(image,&from,target,&to,200,0)==200 && from==3200 && to==210,345);
    CHECK(position(image)==1000 && position(target)==1000 && holds(target,10,3000,200),346);
    from=TEXT;
    CHECK(copy_range(image,&from,target,0,10,0)==0 && from==TEXT && position(target)==1000,347);
    from=TEXT-4;
    CHECK(copy_range(image,&from,target,0,10,0)==4 && from==TEXT && position(target)==1004,348);
    /* One file: overlapping ranges are refused, separate ones copied. */
    long a=0, b=5;
    CHECK(copy_range(target,&a,target,&b,10,0)==-22 && a==0 && b==5,349);
    b=2000;
    CHECK(copy_range(target,&a,target,&b,10,0)==10 && a==10 && b==2010 && holds(target,2000,0,10),350);
    /* Refusals. */
    CHECK(copy_range(image,0,target,0,10,1)==-22 && copy_range(dir,0,target,0,10,0)==-21,351);
    CHECK(copy_range(image,0,dir,0,10,0)==-21 && copy_range(pipe[0],0,target,0,10,0)==-22,352);
    CHECK(copy_range(image,0,null,0,10,0)==-22 && copy_range(image,0,1,0,10,0)==-22,353);
    CHECK(copy_range(image,0,append,0,10,0)==-9 && copy_range(image,0,image,0,10,0)==-9,354);
    CHECK(copy_range(wronly,0,target,0,10,0)==-9 && copy_range(path,0,target,0,10,0)==-9,355);
    CHECK(copy_range(image,(long *)1,target,0,10,0)==-14 && copy_range(image,0,target,(long *)1,10,1)==-14,356);
    CHECK(copy_range(12345,(long *)1,target,0,10,1)==-9 && copy_range(image,0,12345,0,10,0)==-9,357);
    from=-1;
    CHECK(copy_range(image,&from,target,0,10,0)==-75 && copy_range(image,&from,target,0,0,0)==-22,358);
    CHECK(position(image)==1000 && position(target)==1004,359);
    /* Each call moves at most 1 MiB. */
    long second=DO(2,"/work/second",0102,0600); CHECK(second>=3,360);
    CHECK(DO(8,large,0,0)==0 && copy_range(large,0,second,0,3*1024*1024,0)==1024*1024,361);
    CHECK(position(large)==1024*1024 && position(second)==1024*1024,362);
    long closes[]={image,out,copy,null,ascii,large,whole,pipe[0],pipe[1],pair[0],pair[1],dir,append,
        wronly,path,target,second};
    for (unsigned i=0;i<sizeof closes/sizeof *closes;++i) CHECK(DO(3,closes[i],0,0)==0,363);
    static const char *names[]={"/work/out","/work/copy","/work/whole","/work/append","/work/wronly",
        "/work/target","/work/second",0};
    for (int i=0;names[i];++i) CHECK(DO(87,names[i],0,0)==0,364);
    DO(1,1,"transfer: PASS\n",15);
    return 0;
}
/* The confined filesystem has no extended attributes: every xattr call
   resolves its file as stat, lstat or fstat would and then finds none. */
static long xattr_stat(const char *path, int nofollow)
{
    return call(262,AT,(word)path,(word)at,nofollow?NOFOLLOW:0,0,0);
}
static int untouched(void)
{
    for (unsigned i=0;i<sizeof wide;++i) if (wide[i]!=0xa5) return 0;
    return 1;
}
static int xattr_path_parity(const char *path)
{
    clear();
    long s=xattr_stat(path,0), l=xattr_stat(path,1);
    long expect[8]={s==0?-61:s, l==0?-61:l, s==0?0:s, l==0?0:l, s==0?-95:s, l==0?-95:l,
        s==0?-95:s, l==0?-95:l};
    long got[8]={
        call(191,(word)path,(word)"user.ginux",(word)wide,64,0,0),
        call(192,(word)path,(word)"user.ginux",(word)wide,64,0,0),
        DO(194,path,wide,64), DO(195,path,wide,64),
        call(188,(word)path,(word)"user.ginux",(word)"v",1,0,0),
        call(189,(word)path,(word)"user.ginux",(word)"v",1,1,0),
        DO(197,path,"user.ginux",0), DO(198,path,"user.ginux",0)};
    for (int i=0;i<8;++i) if (got[i]!=expect[i]) return 0;
    return untouched();
}
static int xattr_descriptor(long fd, long expect_get, long expect_list, long expect_set)
{
    clear();
    return call(193,fd,(word)"user.ginux",(word)wide,64,0,0)==expect_get
        && DO(196,fd,wide,64)==expect_list
        && call(190,fd,(word)"user.ginux",(word)"v",1,2,0)==expect_set
        && DO(199,fd,"user.ginux",0)==expect_set && untouched();
}
/* The kernel ABI preserves every argument register across a rewritten
   path xattr call. */
static int xattr_preserved(long n, const char *path, long expect)
{
    register word r10 __asm__("r10")=64, r8 __asm__("r8")=0, r9 __asm__("r9")=0x0909;
    word rdi=(word)path, rsi=(word)"user.ginux", rdx=(word)wide;
    long result=n;
    __asm__ volatile("syscall":"+a"(result),"+D"(rdi),"+S"(rsi),"+d"(rdx),"+r"(r10),"+r"(r8),"+r"(r9)::"rcx","r11","memory");
    return result==expect && rdi==(word)path && rsi==(word)"user.ginux" && rdx==(word)wide
        && r10==64 && r8==0 && r9==0x0909;
}
static char long_name[300];
static long xattrs(void)
{
    /* Every form once early, while the audit records all of them. */
    long early=DO(2,"/image-labelled",0,0); CHECK(early>=3,399);
    CHECK(xattr_descriptor(early,-61,0,-95) && DO(3,early,0,0)==0,399);
    long fd=DO(2,"/work/file",0102,0600); CHECK(fd>=3 && DO(3,fd,0,0)==0,400);
    CHECK(DO(83,"/work/dir",0755,0)==0,401);
    CHECK(DO(88,"file","/work/link",0)==0 && DO(88,"missing","/work/dangling",0)==0,402);
    static const char *paths[]={
        "/image","/image-dir","/image-dir/inner","/image-link","/image-dangling","image-link",
        "/bin/../image","/image-dir/../image","/missing","/image/child","/image-link/child",
        "/work/file","/work/dir","/work/link","/work/dangling","/work/missing","/work/file/x",
        "/dev/null","/dev","/dev/missing","/proc/self/maps","/proc","/sys","/image-labelled","",0};
    for (int i=0;paths[i];++i) CHECK(xattr_path_parity(paths[i]),403);
    CHECK(xattr_path_parity((const char *)1),404);
    CHECK(call(191,(word)"/image-link",(word)"user.ginux",(word)wide,64,0,0)==-61,405);
    CHECK(call(191,(word)"/image-dangling",(word)"user.ginux",(word)wide,64,0,0)==-2,406);
    CHECK(call(192,(word)"/image-dangling",(word)"user.ginux",(word)wide,64,0,0)==-61,407);
    CHECK(call(191,(word)"/image/child",(word)"user.ginux",(word)wide,64,0,0)==-20,408);
    /* Host attributes and security labels stay invisible. */
    CHECK(call(191,(word)"/image-labelled",(word)"user.ginux",(word)wide,64,0,0)==-61 && untouched(),409);
    CHECK(call(191,(word)"/image-labelled",(word)"security.selinux",(word)wide,64,0,0)==-61 && untouched(),410);
    CHECK(call(191,(word)"/image-labelled",(word)"security.ginux",(word)wide,64,0,0)==-61 && untouched(),411);
    CHECK(DO(194,"/image-labelled",wide,sizeof wide)==0 && DO(194,"/image-labelled",1,64)==0 && untouched(),412);
    CHECK(DO(194,"/image-labelled",0,0)==0 && DO(195,"/image-labelled",0,0)==0,413);
    /* Names, flags, sizes and values, before the path. */
    CHECK(call(191,(word)"/image",(word)"",(word)wide,64,0,0)==-34,414);
    CHECK(call(191,(word)"/missing",(word)"",(word)wide,64,0,0)==-34,415);
    CHECK(call(191,(word)"/image",1,(word)wide,64,0,0)==-14 && DO(197,"/missing",1,0)==-14,416);
    for (int i=0;i<300;++i) long_name[i]='a';
    CHECK(call(191,(word)"/image",(word)long_name,(word)wide,64,0,0)==-34,417);
    long_name[255]=0;
    CHECK(call(191,(word)"/image",(word)long_name,(word)wide,64,0,0)==-61,418);
    long_name[255]='a'; long_name[256]=0;
    CHECK(call(191,(word)"/image",(word)long_name,(word)wide,64,0,0)==-34,419);
    long page=call(9,0,8192,3,0x22,(word)-1,0); CHECK(page>0 && DO(11,page+4096,4096,0)==0,420);
    char *edge=(char *)page+4096-7;
    for (int i=0;i<6;++i) edge[i]="user.x"[i];
    edge[6]=0;
    CHECK(call(191,(word)"/image",(word)edge,(word)wide,64,0,0)==-61,421);
    edge[6]='y';
    CHECK(call(191,(word)"/image",(word)edge,(word)wide,64,0,0)==-14,422);
    CHECK(DO(11,page,4096,0)==0,423);
    CHECK(call(188,(word)"/image",(word)"user.x",(word)"v",1,4,0)==-22,424);
    CHECK(call(188,(word)"/missing",(word)"user.x",(word)"v",1,4,0)==-22,425);
    CHECK(call(188,(word)"/missing",(word)"",(word)"v",1,0,0)==-34,426);
    CHECK(call(188,(word)"/image",(word)"user.x",(word)"v",65537,0,0)==-7,427);
    CHECK(call(188,(word)"/image",(word)"user.x",1,1,0,0)==-14,428);
    CHECK(call(188,(word)"/missing",(word)"user.x",1,1,0,0)==-14,429);
    CHECK(call(188,(word)"/image",(word)"user.x",1,0,0,0)==-95,430);
    CHECK(call(188,(word)"/image",(word)"user.x",(word)buffer,65536,3,0)==-95,431);
    CHECK(DO(197,"/missing","",0)==-34 && DO(197,"/image","user.x",0)==-95,432);
    /* Descriptor forms: the descriptor first, then the name. */
    long image=DO(2,"/image-labelled",0,0); CHECK(image>=3,433);
    long dir=DO(2,"/image-dir",0200000,0); CHECK(dir>=3,434);
    long owned=DO(2,"/work/file",2,0); CHECK(owned>=3,435);
    long owned_dir=DO(2,"/work/dir",0200000,0); CHECK(owned_dir>=3,436);
    int pipe[2]; CHECK(DO(22,pipe,0,0)==0,437);
    int pair[2]; CHECK(call(53,1,1,0,(word)pair,0,0)==0,438);
    long counter=DO(290,0,0,0); CHECK(counter>=3,439);
    long null=DO(2,"/dev/null",2,0); CHECK(null>=3,440);
    long open_fds[]={image,dir,owned,owned_dir,pipe[0],pipe[1],pair[0],counter,null,0,1,2};
    for (unsigned i=0;i<sizeof open_fds/sizeof *open_fds;++i)
        CHECK(xattr_descriptor(open_fds[i],-61,0,-95),441);
    long path=DO(2,"/image-labelled",010000000,0); CHECK(path>=3,442);
    CHECK(xattr_descriptor(path,-9,-9,-9) && xattr_descriptor(12345,-9,-9,-9) && xattr_descriptor(-1,-9,-9,-9),443);
    CHECK(call(193,12345,(word)"",(word)wide,64,0,0)==-9 && call(193,image,(word)"",(word)wide,64,0,0)==-34,444);
    CHECK(call(190,12345,(word)"user.x",(word)"v",1,4,0)==-9 && call(190,image,(word)"user.x",(word)"v",1,4,0)==-22,445);
    CHECK(call(190,image,(word)"user.x",1,1,0,0)==-14 && DO(199,image,1,0)==-14,446);
    CHECK(DO(196,image,1,64)==0 && DO(196,image,0,0)==0 && untouched(),447);
    /* Registers survive the rewritten path forms in every backend. */
    CHECK(xattr_preserved(191,"/image",-61) && xattr_preserved(192,"/work/link",-61),448);
    CHECK(xattr_preserved(189,"/dev/null",-95) && xattr_preserved(191,"/missing",-2),449);
    CHECK(xattr_preserved(191,"/proc/self/maps",-61),450);
    long closes[]={image,dir,owned,owned_dir,pipe[0],pipe[1],pair[0],pair[1],counter,null,path};
    for (unsigned i=0;i<sizeof closes/sizeof *closes;++i) CHECK(DO(3,closes[i],0,0)==0,451);
    CHECK(DO(87,"/work/file",0,0)==0 && DO(87,"/work/link",0,0)==0 && DO(87,"/work/dangling",0,0)==0,452);
    CHECK(DO(84,"/work/dir",0,0)==0,453);
    DO(1,1,"xattr: PASS\n",12);
    return 0;
}
/* The contract decides each new call by its own operation, and a transfer
   by both of its descriptors. */
static long file_calls_policy(void)
{
    long fd=DO(2,"/image-text",0,0); CHECK(fd>=3,500);
    long out=DO(2,"/work/out",0102,0600); CHECK(out>=3,501);
    struct iov v[1]={{wide,8}};
    CHECK(preadv2_at(fd,v,1,0,0)==-1 && preadv_at(fd,v,1,0)==8,502);
    CHECK(readahead(fd)==-1 && advice(fd,0)==-1,503);
    CHECK(call(191,(word)"/image",(word)"user.x",(word)wide,64,0,0)==-1,504);
    CHECK(call(192,(word)"/image",(word)"user.x",(word)wide,64,0,0)==-61,505);
    CHECK(DO(196,fd,wide,64)==-1 && DO(194,"/image",wide,64)==0,506);
    CHECK(call(189,(word)"/image",(word)"user.x",(word)"v",1,0,0)==-1,507);
    CHECK(call(188,(word)"/image",(word)"user.x",(word)"v",1,0,0)==-95,508);
    CHECK(sendfile_call(out,fd,0,8)==-1 && copy_range(fd,0,out,0,8,0)==-1 && position(fd)==0,509);
    CHECK(DO(3,fd,0,0)==0 && DO(3,out,0,0)==0 && DO(87,"/work/out",0,0)==0,510);
    DO(1,1,"file-calls-policy: PASS\n",24);
    return 0;
}
/* A transfer also reads its input: with console reads denied, a transfer
   from the console is refused by that rule, while one into it is not. */
static long transfer_policy(void)
{
    long fd=DO(2,"/image-ascii",0,0); CHECK(fd>=3,520);
    long out=DO(2,"/work/out",0102,0600); CHECK(out>=3,521);
    CHECK(sendfile_call(out,0,0,8)==-1 && copy_range(0,0,out,0,8,0)==-1,522);
    CHECK(sendfile_call(out,fd,0,4)==4 && sendfile_call(1,fd,0,64)==13,523);
    CHECK(DO(3,fd,0,0)==0 && DO(3,out,0,0)==0 && DO(87,"/work/out",0,0)==0,524);
    DO(1,1,"transfer-policy: PASS\n",22);
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
    if (scenario=='R') return vectored_at();
    if (scenario=='T') return transfers();
    if (scenario=='X') return xattrs();
    if (scenario=='Y') return file_calls_policy();
    if (scenario=='Z') return transfer_policy();
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
