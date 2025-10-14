#include <stdio.h>
#include <stdlib.h>

// Global variable in .bss section
unsigned int global_variable = 0;  // At address 0x804988c

void v() {
    char buffer[512];
    
    fgets(buffer, 512, stdin);
    
    // Format string vulnerability!
    printf(buffer);         // Should be: printf("%s", buffer);
    
    if (global_variable == 64) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main() {
    v();
    return 0;
}