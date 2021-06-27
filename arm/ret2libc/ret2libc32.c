#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *buf[64];
    puts("now gibme input");
    gets(buf);
}

void gadgets() {
    asm("pop {r0, pc}");
    return;
}