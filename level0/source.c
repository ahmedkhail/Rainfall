#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    int input = atoi(argv[1]);
    
    if (input == 423) {
        char *shell_path = strdup("/bin/sh");
        
        gid_t gid = getegid();
        uid_t uid = geteuid();
        
        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);
        
        char *argv[] = {shell_path, NULL};
        execv(shell_path, argv);
        
    } else {
        fwrite("No!\n", 1, 5, stderr);
    }
    
    return 0;
}