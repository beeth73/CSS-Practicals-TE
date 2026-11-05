# Buffer Overflow Demos (gets/strcpy and strcat/sprintf)

A quick note before the code: I'll give you working, compilable demonstrations that show *why* these functions are dangerous — buffers overflowing into adjacent memory and corrupting nearby variables. I'm keeping this at the "memory corruption demo" level (the standard content in security labs like this one) rather than writing shellcode or control-hijacking payloads, since that crosses into exploit-development territory. This is everything you need for the lab's learning objective: understanding *why* bounds-checking matters.

---

## 1. `gets()` and `strcpy()` demo

```c
// bof_gets_strcpy.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Modern glibc removed gets() entirely (too dangerous, dropped in C11).
// This wrapper reproduces the *exact same unsafe behavior* so the demo
// still compiles/runs on current Linux/macOS systems.
char *unsafe_gets(char *buf) {
    int c;
    char *p = buf;
    while ((c = getchar()) != '\n' && c != EOF) {
        *p++ = c;   // <-- no bounds check, just like real gets()
    }
    *p = '\0';
    return buf;
}

void vulnerable_gets_demo() {
    char buffer[8];
    int authenticated = 0;   // sits right after buffer on the stack (typically)

    printf("Enter your name: ");
    unsafe_gets(buffer);     // overflow possible here

    printf("Buffer contains: %s\n", buffer);
    if (authenticated != 0)
        printf("OVERFLOW! 'authenticated' got overwritten -> %d\n", authenticated);
    else
        printf("authenticated = %d (unchanged)\n", authenticated);
}

void vulnerable_strcpy_demo(char *input) {
    char buffer[8];
    strcpy(buffer, input);   // no length check -> overflow if input > 7 chars
    printf("Copied: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    printf("--- gets() demo ---\n");
    vulnerable_gets_demo();

    printf("\n--- strcpy() demo ---\n");
    if (argc > 1)
        vulnerable_strcpy_demo(argv[1]);
    else
        vulnerable_strcpy_demo("AAAAAAAAAAAAAAAAAAAA"); // 20 chars into 8-byte buffer
    return 0;
}
```

## 2. `strcat()` and `sprintf()` demo

```c
// bof_strcat_sprintf.c
#include <stdio.h>
#include <string.h>

void vulnerable_strcat_demo() {
    char buffer[16];
    int canary = 0x11223344;  // marker variable placed after buffer

    strcpy(buffer, "Hello, ");
    strcat(buffer, "this string is way too long for the buffer!"); // overflow

    printf("Buffer: %s\n", buffer);
    printf("Canary: 0x%x %s\n", canary,
           canary != 0x11223344 ? "<-- OVERWRITTEN!" : "(unchanged)");
}

void vulnerable_sprintf_demo(const char *name) {
    char buffer[10];
    sprintf(buffer, "Hello, %s!", name);  // no length limit -> overflow
    printf("%s\n", buffer);
}

int main(int argc, char *argv[]) {
    printf("--- strcat() demo ---\n");
    vulnerable_strcat_demo();

    printf("\n--- sprintf() demo ---\n");
    vulnerable_sprintf_demo(argc > 1 ? argv[1] : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return 0;
}
```

---

## Compile & run commands

**Linux (gcc):**
```bash
gcc -g -fno-stack-protector -z execstack -no-pie -o bof1 bof_gets_strcpy.c
gcc -g -fno-stack-protector -z execstack -no-pie -o bof2 bof_strcat_sprintf.c

./bof1
./bof1 AAAAAAAAAAAAAAAAAAAAAAAA
./bof2
```

**macOS (clang):**
```bash
clang -g -fno-stack-protector -o bof1 bof_gets_strcpy.c
clang -g -fno-stack-protector -o bof2 bof_strcat_sprintf.c

./bof1
./bof1 AAAAAAAAAAAAAAAAAAAAAAAA
./bof2
```
> Note: `-z execstack` is a Linux linker flag and isn't supported by macOS's linker, so it's dropped above. macOS also has additional hardening (SIP, ASLR by default) that you can't fully disable, so results may vary run to run.

The `-fno-stack-protector` flag intentionally disables the compiler's stack canary so the overflow isn't caught before you can observe it — that's standard for teaching demos like this one, never for production code.

---

## Justification for deliberately overflowing the buffer

In a lab/educational setting, intentionally triggering an overflow is valuable because it demonstrates:

1. **Root cause of a real vulnerability class.** `gets()`, `strcpy()`, `strcat()`, and unbounded `sprintf()` never check destination size, so attacker-controlled input can write past the allocated buffer. This is the mechanism behind decades of real CVEs (including the 1988 Morris Worm, which used a `gets()` overflow).
2. **Memory layout intuition.** Seeing an adjacent variable (`authenticated`, `canary`) change value *without being directly assigned* makes the abstract idea of "stack memory" concrete — variables are just bytes sitting next to each other.
3. **Why defenses exist.** Once you've seen a canary get clobbered, concepts like stack canaries, ASLR, DEP/NX, and `-fstack-protector` make intuitive sense instead of being arbitrary checklist items.
4. **Motivates safer coding habits.** The natural next step is replacing these calls with bounds-checked equivalents: `fgets()` instead of `gets()`, `strncpy()`/`strlcpy()` instead of `strcpy()`, `strncat()`/`strlcat()` instead of `strcat()`, and `snprintf()` instead of `sprintf()`.

This kind of demo should only run against your own code, in a local VM or sandbox you control — not against systems or software you don't own, since unauthorized memory-corruption attacks against real systems are illegal.

If your lab's next step is comparing these against the "safe" versions, I'm happy to write that side-by-side too.