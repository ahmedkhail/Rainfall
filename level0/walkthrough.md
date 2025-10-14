# Level 0

## Initial Analysis

### 1. Examine the Binary
```bash
level0@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level0 level0   80 Mar  6  2016 .
drwxr-x--x  1 root   users   340 Sep 23  2015 ..
-rw-r--r--  1 level0 level0  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level0 level0 3530 Apr  3  2012 .bashrc
-rwsr-s---+ 1 level1 users  5403 Mar  6  2016 level0
-rw-r--r--  1 level0 level0  675 Apr  3  2012 .profile

level0@RainFall:~$ file level0
level0: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=0x85cf4024dbe79c7ccf4f30e7c601a356ce04f412, not stripped
```

**Key observations:**
- **setuid binary** (s flag in permissions)
- Owned by **level1** user
- When executed, runs with **level1 privileges**

### 2. Test Basic Execution
```bash
level0@RainFall:~$ ./level0
Segmentation fault (core dumped)

level0@RainFall:~$ ./level0 test
No!

level0@RainFall:~$ ./level0 hello
No!
```

**Findings:**
- Program crashes without arguments
- With arguments, prints "No!" and exits
- Expecting specific input

## Reverse Engineering

### 3. Disassembly Analysis
```bash
level0@RainFall:~$ gdb ./level0
(gdb) disas main
```

**Critical code section:**
```assembly
0x08048ed4 <+20>:    call   0x8049710 <atoi>      # Convert argv[1] to integer
0x08048ed9 <+25>:    cmp    eax,0x1a7             # Compare with 0x1a7
0x08048ede <+30>:    jne    0x8048f58 <main+152>  # Jump to error if not equal
```

**Analysis:**
- Program calls `atoi()` on first argument
- Compares result with `0x1a7`
- If not equal, jumps to error message

### 4. Find the Magic Number
```bash
level0@RainFall:~$ python -c "print(0x1a7)"
423
```

**The program expects the input `423`**

## Exploitation

### 5. Test the Discovery
```bash
level0@RainFall:~$ ./level0 423
$ whoami
level1
$ id
uid=2030(level1) gid=2020(level0) groups=2030(level1),100(users),2020(level0)
```

**Success!** The program:
1. Accepts `423` as valid input
2. Escalates privileges to level1
3. Executes `/bin/sh` with level1 privileges

### 6. Retrieve the Flag
```bash
$ ls /home/user/level1/
level1
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
$ exit
level0@RainFall:~$
```

## Verification Steps

### Alternative Discovery Methods:

**Method 1: GDB Dynamic Analysis**
```bash
(gdb) break *0x08048ed9
(gdb) run 100
(gdb) print $eax
$1 = 100
(gdb) print 0x1a7
$2 = 423
```