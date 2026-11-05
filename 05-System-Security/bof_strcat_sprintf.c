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