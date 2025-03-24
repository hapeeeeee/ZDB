#include <cstdio> 
#include <numeric>
#include <unistd.h>
#include <signal.h>

void an_innocent_function() {
    std::puts("Putting pineapple on pizza...");
}

void an_innocent_function_end() {}

int checksum() {
    auto start = reinterpret_cast<volatile const char*>(&an_innocent_function);
    auto end = reinterpret_cast<volatile const char*>(&an_innocent_function_end);
    return std::accumulate(start, end, 0);
}

int main() {
    auto safe_num = checksum();

    auto ptr = reinterpret_cast<volatile const char*>(&an_innocent_function);
    write(STDOUT_FILENO, &ptr, sizeof(void*));
    fflush(stdout);
    raise(SIGTRAP);

    while (true) {
        sleep(1);
        if (checksum() == safe_num) {
            an_innocent_function();
        } else {
            std::puts("Putting pepperoni on pizza...");
        }

        fflush(stdout);
        raise(SIGTRAP);
    }
}
