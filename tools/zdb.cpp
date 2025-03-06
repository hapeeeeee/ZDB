#include <algorithm>
#include <editline/readline.h>
#include <iostream>
#include <libzdb/libzdb.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
namespace {
    pid_t attach(int argc, char **argv) {
        pid_t pid = 0;
        // Passing PID
        if (argc == 3 && std::string_view(argv[1]) == "-p") {
            pid = std::atoi(argv[2]);
            if (pid <= 0) {
                std::cerr << "Invalid PID: " << argv[2] << std::endl;
                return -1;
            }
            if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
                std::perror("Failed to attach to process");
                return -1;
            }
        }
        // Passing program name
        else {
            const char *program_name = argv[1];
            pid                      = fork();
            if (pid < 0) {
                std::perror("Failed to fork");
                return -1;
            } else if (pid == 0) {
                // Now in child process, execute the debuggee
                if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
                    std::perror("Failed to set tracing to child process");
                    return -1;
                }
                if (execlp(program_name, program_name, nullptr) < 0) {
                    std::perror("Failed to execute program");
                    return -1;
                }
            }
        }
        return pid;
    }

    std::vector<std::string> split(std::string_view str, char delimiter) {
        std::vector<std::string> result;
        std::stringstream ss{std::string{str}};
        std::string item;
        while (std::getline(ss, item, delimiter)) {
            result.push_back(item);
        }
        return result;
    }

    bool is_prefix(std::string_view str, std::string_view of) {
        if (str.size() > of.size()) {
            return false;
        }
        return std::equal(str.begin(), str.end(), of.begin());
    }

    void resume(pid_t pid) {
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
            std::perror("Failed to continue execution\n");
            std::exit(-1);
        }
    }

    void wait_on_signal(pid_t pid) {
        int wait_status;
        if (waitpid(pid, &wait_status, 0) < 0) {
            std::perror("Failed to wait for child process");
            std::exit(-1);
        }
    }

    void handle_command(pid_t pid, std::string_view line) {
        auto args    = split(line, ' ');
        auto command = args[0];
        if (is_prefix(command, "continue")) {
            resume(pid);
            wait_on_signal(pid);
        } else {
            std::cerr << "Unknown command: " << command << std::endl;
        }
    }

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " No arguments provided\n" << std::endl;
        return 1;
    }

    pid_t pid = attach(argc, argv);
    if (pid == -1) {
        std::cerr << "Failed to attach\n" << std::endl;
        return 1;
    }

    int wait_status;
    // In parent process
    if (waitpid(pid, &wait_status, 0) < 0) {
        std::perror("Failed to wait for child process");
    }

    char *line = nullptr;
    while ((line = readline("zdb> ")) != nullptr) {
        std::string line_string;
        if (line == std::string_view("")) {
            if (history_length > 0) {
                line_string = history_get(history_length - 1)->line;
            }
        } else {
            line_string = line;
            add_history(line);
        }
        free(line);

        if (!line_string.empty()) {
            handle_command(pid, line_string);
        }
    }
}
