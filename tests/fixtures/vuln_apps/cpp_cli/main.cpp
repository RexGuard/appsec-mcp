#include <cstdio>
#include <cstring>

int main(int argc, char **argv) {
    char name[32];
    char greeting[64];

    printf("Your name: ");
    gets(name);

    if (argc > 1) {
        strcpy(name, argv[1]);
    }

    sprintf(greeting, "Hello, %s", name);
    printf(greeting);
    printf("\n");
    return 0;
}
