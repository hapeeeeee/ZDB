#include <editline/readline.h>
#include <libzdb/error.hpp>
#include <libzdb/process.hpp>
#include <string.h>
#include <vector>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <libzdb/parse.hpp>

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


    zdb::Registers::Value parse_register_value(zdb::RegisterInfo info, std::string_view text) {
        try {
            if (info.format == zdb::RegisterFormat::uint) {
                switch (info.size) {
                    case 1: return zdb::to_integral<std::uint8_t>(text, 16).value();
                    case 2: return zdb::to_integral<std::uint16_t>(text, 16).value();
                    case 4: return zdb::to_integral<std::uint32_t>(text, 16).value();
                    case 8: return zdb::to_integral<std::uint64_t>(text, 16).value();
                }
            }
            else if (info.format == zdb::RegisterFormat::double_float) {
                return zdb::to_float<double>(text).value();
            }
            else if (info.format == zdb::RegisterFormat::long_double) {
                return zdb::to_float<long double>(text).value();
            }
            else if (info.format == zdb::RegisterFormat::vector) {
                if (info.size == 8) {
                    return zdb::parse_vector<8>(text);
                }
                else if (info.size == 16) {
                    return zdb::parse_vector<16>(text);
                }
            }
        }
        catch (...) {}

        // unreacheable
        zdb::Error::send("Invalid format");
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

    void print_help(const std::vector<std::string> &args) {
        if (args.size() == 1) {
            std::cerr << R"(Available commands:
                continue - Resume the process
                register - Commands for operating on registers)" << std::endl;
        } else if (args[1] == "register") {
            std::cerr << R"(Available commands:
            read
            read <register>
            read all
            write <register> <value>)" << std::endl;
        } else {
            std::cerr << "No help available on that\n";
        }
    }

    void handle_register_read_command(const zdb::Process &process, const std::vector<std::string> &args) {
        auto fn_format = [](auto t) -> std::string {
            if constexpr (std::is_floating_point_v<decltype(t)>) {
                return fmt::format("{}", t);
            } else if constexpr (std::is_integral_v<decltype(t)>) {
                return fmt::format("{:#0{}x}", t, sizeof(t) * 2 + 2);
            } else {
                return fmt::format("[{:#04x}]", fmt::join(t, ","));
            }
        };
        
        if (args.size() == 2                        ///< register read
            || args.size() == 3 && args[2] == "all" ///< register read all
        ) {
            for (auto reg_info : zdb::g_register_infos) {
                bool should_print = (reg_info.type == zdb::RegisterType::gpr && reg_info.name != "orig_rax");
                if (!should_print) continue;

                auto value = process.get_registers().read(reg_info);
                fmt::print("{}:\t{}\n", reg_info.name, std::visit(fn_format, value));
            }
        } else if (args.size() == 3) {             ///< register read <register>
            try {
                auto reg_info = zdb::find_register_info_by_name(args[2]);
                auto value = process.get_registers().read(reg_info);
                fmt::print("{}:\t{}\n", reg_info.name, std::visit(fn_format, value));
            } catch (const zdb::Error &e) {
                std::cerr << "No such register\n";
                return;
            }
        } else {
            print_help({ "help", "register" });
        }
        
    }

    void handle_register_write_command(zdb::Process &process, const std::vector<std::string> &args) {
        if (args.size() != 4) {   ///< register write <register> <value>
            print_help({ "help", "register"});
            return;
        }

        try {
            auto reg_info = zdb::find_register_info_by_name(args[2]);
            auto value = parse_register_value(reg_info, args[3]);
            process.get_registers().write(reg_info, value);
        } catch (const zdb::Error &e) {
            std::cerr << e.what() << std::endl;
            return;
        }
    }

    void handle_register_command(const zdb::Process &process, const std::vector<std::string> &args) {
        if (args.size() < 2) {
            print_help({"help", "register"});
            return;
        } 
        
        if (args[1] == "read") {
            handle_register_read_command(process, args);
        } else if (args[1] == "write") {
            handle_register_write_command(process, args);
        } else {
            print_help({"help", "register"});
        }
    }

    void handle_command(std::unique_ptr<zdb::Process> &process, std::string_view line) {
        auto args    = split(line, ' ');
        auto command = args[0];
        if (is_prefix(command, "continue")) {
            process->resume();
            zdb::StopReason stop_reason = process->wait_on_signal();
            print_stop_reason(*process, stop_reason);
        } else if (is_prefix(command, "help")) {
            print_help(args);
        } else if (is_prefix(command, "register")) {
            handle_register_command(*process, args);
        }
        else {
            std::cerr << "Unknown command\n";
        }
    }

    void main_loop(std::unique_ptr<zdb::Process> &proc) {
        char *line = nullptr;
        while ((line = readline("zdb> ")) != nullptr) {
            std::string line_string;
            if (line == std::string_view("")) {
                if (history_length > 0) {
                    line_string = history_list()[history_length - 1]->line;
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
