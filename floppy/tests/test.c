#include <stdarg.h>
#include <stdio.h>
int main(int argc, char *argv[]) {
    printf("hi, mom\n");
    printf("argc: %d\n", argc);
    int i;
    for (i = 0; i < argc; i++)
        printf("%s\n", argv[i]);
    return 0;
}
