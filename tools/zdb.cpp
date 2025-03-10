#include <editline/readline.h>
#include <libzdb/error.hpp>
#include <libzdb/process.hpp>
#include <string.h>
#include <vector>

namespace {
    std::unique_ptr<zdb::Process> attach(int argc, const char **argv) {
        // Passing PID
        if (argc == 3 && argv[1] == std::string_view("-p")) {
            pid_t pid = std::atoi(argv[2]);
            return zdb::Process::attach(pid);
        }
        // Passing program name
        else {
            const char *program_path = argv[1];
            return zdb::Process::launch(program_path);
        }
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

    void print_stop_reason(const zdb::Process &process, zdb::StopReason &stop_reason) {
        std::cout << "Process " << process.pid() << ' ';

        switch (stop_reason.reason) {
        case zdb::ProcessState::Stopped:
            std::cout << "stoped with status" << stop_reason.info;
            break;
        case zdb::ProcessState::Exited:
            std::cout << "exited with status" << sigabbrev_np(stop_reason.info);
            break;
        case zdb::ProcessState::Terminated:
            std::cout << "terminated with status" << sigabbrev_np(stop_reason.info);
            break;
        }
        std::cout << std::endl;
    }

    void handle_command(std::unique_ptr<zdb::Process> &process, std::string_view line) {
        auto args    = split(line, ' ');
        auto command = args[0];
        if (is_prefix(command, "continue")) {
            process->resume();
            zdb::StopReason stop_reason = process->wait_on_signal();
            print_stop_reason(*process, stop_reason);
        } else {
            std::cerr << "Unknown command\n";
        }
    }

    void main_loop(std::unique_ptr<zdb::Process> &proc) {
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
                try {
                    handle_command(proc, line_string);
                } catch (zdb::Error &e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
            }
        }
    }
} // namespace

int main(int argc, const char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " No arguments provided\n" << std::endl;
        return 1;
    }

    try {
        auto process = attach(argc, argv);
        main_loop(process);
    } catch (const zdb::Error &err) {
        std::cout << err.what() << '\n';
    }
}
