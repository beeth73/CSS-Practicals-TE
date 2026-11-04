#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void login_system(char *user_input) {
    // 1. The Stack Layout (Variables sit next to each other in memory)
    int auth_flag = 0;             // 0 means NOT authenticated
    char password_buffer[10];      // Can only hold 9 characters + \0

    // ==========================================
    // EXP 21: strcpy() vulnerability
    // ==========================================
    // strcpy copies the user input into the buffer without checking the size!
    strcpy(password_buffer, user_input); 

    // ==========================================
    // EXP 22: strcat() & sprintf() vulnerabilities (Alternative examples)
    // ==========================================
    // strcat(password_buffer, user_input);   // Appends blindly!
    // sprintf(password_buffer, "%s", user_input); // Formats blindly!

    // The Logic Check
    if (strcmp(password_buffer, "SecretKey") == 0) {
        auth_flag = 1;
    }

    // THE EXPLOIT CHECK
    // If we typed 15 'A's, auth_flag gets overwritten by the ASCII value of 'A' (which is not 0).
    if (auth_flag != 0) {
        printf("\n[+] ACCESS GRANTED! Welcome, Admin.\n");
        printf("    Buffer holds: %s\n", password_buffer);
        printf("    auth_flag value: %d\n", auth_flag);
    } else {
        printf("\n[-] ACCESS DENIED!\n");
        printf("    auth_flag value is still: %d\n", auth_flag);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./overflow <password>\n");
        return 1;
    }
    
    printf("--- BUFFER OVERFLOW SIMULATION ---\n");
    login_system(argv[1]);
    return 0;
}