#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void p() {
    char buffer[76];        
    void *ret_addr;         
    
    fflush(stdout);
    gets(buffer);
    
    ret_addr = __builtin_return_address(0);
    
    // Check if return address points to prohibited memory range
    if (((unsigned int)ret_addr & 0xb0000000) == 0xb0000000) {
        printf("Error: %p\n", ret_addr);  // Format string at 0x8048620
        _exit(1);
    }
    
    puts(buffer);           
    strdup(buffer);         // Copy to heap (heap addr typically 0x0804a008)
}

int main() {
    p();                   
    return 0;
}