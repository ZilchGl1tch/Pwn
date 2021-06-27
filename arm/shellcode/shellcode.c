#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    unsigned char *shell = malloc(0x100);
    mprotect(shell,0x100,7); 
    printf("Enter shellcode: ");
    fgets(shell,0x100,stdin);

    int (*ptr)() = (int(*)())shell;
    ptr();
}
