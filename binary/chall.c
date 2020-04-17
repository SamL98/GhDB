#include <stdio.h>

void win() {
    printf("Congrats! You won!\n");
}

int main() {
    char buffer[10];

    printf("Enter your name: ");
    gets(buffer);

    printf("Hello, %s!\n", buffer);
}
