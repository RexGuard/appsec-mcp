#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    char name[32];
    char line[64];
    if (argc > 1) {
        strcpy(name, argv[1]);
    }
    gets(line);
    printf(line);
    printf("\nHello %s\n", name);
    return 0;
}
