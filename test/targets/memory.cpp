#include <cstdio>
#include <sys/signal.h>
#include <unistd.h>
int main() {
    unsigned long long a = 0xcafecafe;
    auto a_address = &a;
    auto address_of_a_address = &a_address;
    write(STDOUT_FILENO, address_of_a_address, sizeof(void*));
    fflush(stdout);
    raise(SIGTRAP);

    char buf[12] = {0};
    auto buf_address = &buf;
    auto address_of_buf_address = &buf_address;
    write(STDOUT_FILENO, address_of_buf_address, sizeof(void*));
    fflush(stdout);
    raise(SIGTRAP);

    printf("%s", buf);
    fflush(stdout);
}