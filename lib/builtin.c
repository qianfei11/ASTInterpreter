#include <stdio.h>
#include <stdlib.h>

int GET() {
    int x;
    scanf("%d", &x);
    return x;
}
void* MALLOC(int sz) {
    return malloc(sz);
}
void FREE(void * ptr) {
    free(ptr);
}
void PRINT(int x) {
    printf("%d", x);
}
