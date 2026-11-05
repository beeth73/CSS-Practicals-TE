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