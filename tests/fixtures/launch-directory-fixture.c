/* Public owned directory handles, x86-64 dirents and relative operations. */
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
static char buffer[4096] __attribute__((aligned(8)));
static char meta[256] __attribute__((aligned(8)));
static const char readonly_buffer[64] = "readonly";
static int equal(const char *a, const char *b)
{ while (*a && *a==*b) { ++a; ++b; } return *a==*b; }
static long create(const char *path, const char *data)
{
    long fd=DO(2,path,0102,0600); if (fd<0) return fd;
    word n=0; while (data[n]) ++n;
    if (DO(1,fd,data,n)!=(long)n) return -1;
    if (DO(3,fd,0,0)!=0) return -1;
    return 0;
}
long directory_main(word *stack)
{
    if (*stack > 1) {
        CHECK(DO(79,buffer,sizeof buffer,0)==16 && equal(buffer,"/work/cwd-moved"),120);
        CHECK(create("exec-output","exec")==0,121);
        return 0;
    }
    CHECK(DO(83,"/work/dir",0755,0)==0 && DO(83,"/work/dir/sub",0755,0)==0,10);
    CHECK(create("/work/dir/file","file-content")==0 && create("/work/dir/sub/leaf","leaf")==0,11);
    CHECK(DO(2,"/work/dir/file",0200000,0)==-20 && DO(2,"/work/missing",0200000,0)==-2,12);
    CHECK(DO(2,"/work/dir",1,0)==-21 && DO(2,"/work/dir",0200100,0)==-22,13);
    long dir=DO(2,"/work/dir",02204000,0), alias=DO(32,dir,0,0);
    CHECK(dir>=3 && alias>=3 && DO(72,dir,1,0)==1 && DO(72,dir,3,0)==04000,14);
    CHECK(DO(5,dir,meta,0)==0 && (*(unsigned int *)(meta+24)&0170000)==0040000,15);
    word inode=*(word *)(meta+8);
    CHECK(DO(0,dir,buffer,1)==-21 && DO(217,dir,buffer,1)==-22 && DO(8,dir,0,1)==0,16);
    CHECK(DO(217,dir,1,sizeof buffer)==-14 && DO(217,dir,readonly_buffer,64)==-14,17);
    CHECK(DO(8,alias,0,1)==0,18);
    long pages=call(9,0,8192,3,0x22,-1,0);
    CHECK(pages>0 && DO(10,pages+4096,4096,0)==0,19);
    CHECK(DO(217,dir,pages+4094,4096)==-14 && DO(8,dir,0,1)==0,20);
    CHECK(DO(11,pages,8192,0)==0,21);
    CHECK(DO(217,dir,buffer,24)==24 && equal(buffer+19,".") && *(word *)buffer==inode,22);
    CHECK(DO(217,alias,buffer,24)==24 && equal(buffer+19,".."),23);
    CHECK(DO(8,dir,0,0)==0,24);
    long count=DO(217,alias,buffer,sizeof buffer); CHECK(count>0,25);
    unsigned int names=0;
    for (word offset=0;offset<(word)count;) {
        char *entry=buffer+offset;
        word length=*(unsigned short *)(entry+16);
        CHECK(length>=24 && length%8==0 && offset+length<=(word)count,26);
        CHECK(*(word *)entry>0 && *(word *)entry<=4097,27);
        if (equal(entry+19,".")) { names|=1; CHECK(entry[18]==4,28); }
        else if (equal(entry+19,"..")) { names|=2; CHECK(entry[18]==4,29); }
        else if (equal(entry+19,"sub")) { names|=4; CHECK(entry[18]==4,30); }
        else if (equal(entry+19,"file")) { names|=8; CHECK(entry[18]==8,31); }
        else return 32;
        offset+=length;
    }
    CHECK(names==15 && DO(217,dir,1,4096)==0,33);
    long file=DO(257,dir,"file",0);
    CHECK(file>=3 && DO(0,file,buffer,12)==12 && equal(buffer,"file-content"),34);
    CHECK(call(262,dir,(word)"sub/leaf",(word)meta,0,0,0)==0 && *(word *)(meta+48)==4,35);
    CHECK(DO(258,alias,"next",0755)==0,36);
    CHECK(DO(257,file,"child",0)==-20 && DO(257,1048576,"file",0)==-9,37);
    CHECK(DO(257,dir,"../../image",0)==-95,38);
    long absolute=DO(257,123,"/image",0); CHECK(absolute>=3 && DO(3,absolute,0,0)==0,39);
    CHECK(DO(263,alias,"file",0)==0 && DO(4,"/work/dir/file",meta,0)==-2,40);
    CHECK(DO(8,file,0,0)==0 && DO(0,file,buffer,12)==12 && DO(3,file,0,0)==0,41);
    CHECK(DO(8,dir,0,0)==0,42);
    long child=DO(57,0,0,0); CHECK(child>=0,43);
    if (child==0) return DO(217,alias,buffer,24)==24 && equal(buffer+19,".") ? 0 : 44;
    int status=-1;
    CHECK(DO(61,child,&status,0)==child && status==0,45);
    CHECK(DO(217,dir,buffer,24)==24 && equal(buffer+19,".."),46);
    CHECK(create("/work/dir/from","new-source")==0 && create("/work/target","old-target")==0,48);
    long from=DO(2,"/work/dir/from",0,0), target=DO(2,"/work/target",0,0);
    CHECK(from>=3 && target>=3 && DO(5,from,meta,0)==0,49);
    word from_inode=*(word *)(meta+8);
    CHECK(DO(82,"/work/dir/from","/work/target",0)==0 && DO(4,"/work/dir/from",meta,0)==-2,50);
    CHECK(DO(4,"/work/target",meta,0)==0 && *(word *)(meta+8)==from_inode,51);
    CHECK(DO(0,target,buffer,10)==10 && buffer[0]=='o',52);
    CHECK(DO(0,from,buffer,10)==10 && buffer[0]=='n' && DO(3,target,0,0)==0 && DO(3,from,0,0)==0,53);
    CHECK(DO(82,"/work/dir","/work/moved",0)==0,54);
    CHECK(DO(5,dir,meta,0)==0 && *(word *)(meta+8)==inode,55);
    long leaf=DO(257,alias,"sub/leaf",0); CHECK(leaf>=3 && DO(0,leaf,buffer,4)==4 && buffer[0]=='l',56);
    CHECK(DO(3,leaf,0,0)==0 && DO(4,"/work/dir/sub/leaf",meta,0)==-2,57);
    CHECK(DO(258,dir,"later",0755)==0 && DO(84,"/work/moved",0,0)==-39,58);
    CHECK(DO(84,"/work",0,0)==-16 && DO(84,"/work/target",0,0)==-20 && DO(87,"/work/moved",0,0)==-21,59);
    CHECK(DO(82,"/work/moved","/work/moved/sub/bad",0)==-22,60);
    CHECK(DO(83,"/work/full",0755,0)==0 && create("/work/full/block","block")==0,61);
    CHECK(DO(82,"/work/moved","/work/full",0)==-39 && DO(82,"/work/target","/work/full",0)==-21,62);
    CHECK(DO(82,"/work/moved","/work/target",0)==-20 && DO(82,1,"/work/no-effect",0)==-14,63);
    long full=DO(2,"/work/full",0200000,0), sub=DO(257,dir,"sub",0200000);
    CHECK(full>=3 && sub>=3,64);
    CHECK(call(264,dir,(word)"sub/leaf",full,(word)"renamed-leaf",0,0)==0,65);
    CHECK(DO(263,dir,"sub",0x200)==0 && DO(217,sub,buffer,4096)==0,66);
    CHECK(DO(5,sub,meta,0)==0 && (*(unsigned int *)(meta+24)&0170000)==0040000,67);
    CHECK(DO(257,sub,"new-child",0101)==-2 && DO(3,sub,0,0)==0,68);
    CHECK(call(316,dir,(word)"later",full,(word)"block",1,0)==-17,69);
    CHECK(call(316,dir,(word)"later",full,(word)"block",2,0)==-95,70);
    CHECK(call(316,dir,(word)"later",full,(word)"fresh",1,0)==0 && DO(263,full,"fresh",0x200)==0,71);
    CHECK(DO(82,"/work/moved","/image",0)==-18 && DO(82,"/work","/work-other",0)==-18,72);
    CHECK(DO(84,"/work/seed",0,0)==0 && DO(83,"/work/seed",0755,0)==0,73);
    CHECK(DO(91,full,0040750,0)==0 && DO(5,full,meta,0)==0 && (*(unsigned int *)(meta+24)&0777)==0750,74);
    CHECK(DO(91,full,04755,0)==-13,75);
    CHECK(DO(3,full,0,0)==0 && DO(3,alias,0,0)==0 && DO(3,dir,0,0)==0,47);
    CHECK(create("/work/link-source","shared")==0,130);
    CHECK(DO(86,"/work/link-source","/work/link-alias",0)==0,131);
    CHECK(DO(4,"/work/link-source",meta,0)==0 && *(word *)(meta+16)==2,132);
    word shared_inode=*(word *)(meta+8);
    CHECK(DO(4,"/work/link-alias",meta,0)==0 && *(word *)(meta+8)==shared_inode && *(word *)(meta+16)==2,133);
    long linked=DO(2,"/work/link-alias",2,0); CHECK(linked>=3 && DO(1,linked,"S",1)==1,134);
    CHECK(DO(82,"/work/link-source","/work/link-alias",0)==0 && DO(4,"/work/link-source",meta,0)==0,135);
    CHECK(DO(87,"/work/link-source",0,0)==0 && DO(5,linked,meta,0)==0 && *(word *)(meta+16)==1,136);
    CHECK(DO(82,"/work/link-alias","/work/link-renamed",0)==0 && DO(4,"/work/link-renamed",meta,0)==0 && *(word *)(meta+8)==shared_inode,137);
    long linked_dir=DO(2,"/work",0200000,0); CHECK(linked_dir>=3,138);
    CHECK(call(265,linked_dir,(word)"link-renamed",linked_dir,(word)"link-third",0,0)==0,139);
    CHECK(DO(3,linked_dir,0,0)==0 && DO(90,"/work/link-third",0700,0)==0,140);
    CHECK(DO(5,linked,meta,0)==0 && (*(unsigned int *)(meta+24)&0777)==0700 && *(word *)(meta+16)==2,141);
    CHECK(DO(87,"/work/link-renamed",0,0)==0 && DO(87,"/work/link-third",0,0)==0,142);
    CHECK(DO(5,linked,meta,0)==0 && *(word *)(meta+16)==0 && DO(8,linked,0,0)==0,143);
    CHECK(DO(0,linked,buffer,6)==6 && buffer[0]=='S' && DO(3,linked,0,0)==0,144);
    CHECK(DO(86,"/image","/work/image-link",0)==-18 && DO(86,"/work","/work/dir-link",0)==-13,145);
    CHECK(DO(83,"/work/cwd",0755,0)==0 && DO(83,"/work/cwd/nested",0755,0)==0,80);
    CHECK(DO(80,"/work/cwd",0,0)==0,81);
    CHECK(DO(79,buffer,sizeof buffer,0)==10 && equal(buffer,"/work/cwd"),82);
    CHECK(DO(79,buffer,9,0)==-34 && DO(79,buffer,0,0)==-22 && DO(79,1,4096,0)==-14,83);
    CHECK(create("relative","owned")==0 && DO(80,"relative",0,0)==-20,84);
    long cwd=DO(2,".",0200000,0); CHECK(cwd>=3,85);
    CHECK(DO(81,12345,0,0)==-9 && DO(80,"missing",0,0)==-2,86);
    long child2=DO(57,0,0,0); CHECK(child2>=0,87);
    if (child2==0) {
        CHECK(DO(80,"nested",0,0)==0 && create("child","child")==0,88);
        CHECK(DO(79,buffer,sizeof buffer,0)==17 && equal(buffer,"/work/cwd/nested"),89);
        return 0;
    }
    CHECK(DO(61,child2,&status,0)==child2 && status==0,90);
    CHECK(DO(79,buffer,sizeof buffer,0)==10 && equal(buffer,"/work/cwd"),91);
    CHECK(DO(82,"/work/cwd","/work/cwd-moved",0)==0,92);
    CHECK(DO(79,buffer,sizeof buffer,0)==16 && equal(buffer,"/work/cwd-moved"),93);
    CHECK(DO(80,"/bin",0,0)==0 && DO(79,buffer,sizeof buffer,0)==5 && equal(buffer,"/bin"),94);
    CHECK(DO(81,cwd,0,0)==0 && DO(3,cwd,0,0)==0,95);
    long child3=DO(57,0,0,0); CHECK(child3>=0,96);
    if (child3==0) {
        char *args[]={"fixture","cwd-child",0}, *env[]={0};
        DO(59,"/bin/fixture",args,env);
        return 97;
    }
    CHECK(DO(61,child3,&status,0)==child3 && status==0,98);
    CHECK(DO(4,"exec-output",meta,0)==0 && *(word *)(meta+48)==4,99);
    CHECK(DO(83,"empty",0755,0)==0 && DO(80,"empty",0,0)==0,100);
    CHECK(DO(84,"/work/cwd-moved/empty",0,0)==0,101);
    CHECK(DO(79,buffer,sizeof buffer,0)==-2 && create("hidden","bad")==-2,102);
    CHECK(DO(80,"/bin",0,0)==0,103);
    long bin=DO(2,"/bin",0200000,0); CHECK(bin>=3,104);
    CHECK(DO(80,"/work",0,0)==0 && DO(81,bin,0,0)==0 && DO(3,bin,0,0)==0,105);
    CHECK(DO(79,buffer,sizeof buffer,0)==5 && equal(buffer,"/bin"),106);
    DO(1,1,"owned-directories: PASS\n",24);
    return 0;
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall directory_main\nmov %rax,%rdi\nmov $60,%rax\nsyscall\nud2\n");
