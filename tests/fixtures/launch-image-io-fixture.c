/* Configured image I/O, virtual statfs and child-only virtual credentials. */
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
long image_io_main(word *stack)
{
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
