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
            auto proc = zdb::Process::launch(program_path);
            fmt::print("Process {} launched\n", proc->pid());
            return proc;
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
                    return zdb::parse_vector<8>(text).value();
                }
                else if (info.size == 16) {
                    return zdb::parse_vector<16>(text).value();
                }
            }
        }
        catch (...) {}

        // unreacheable
        zdb::Error::send("Invalid format");
    }
    


    void print_stop_reason(const zdb::Process &process, zdb::StopReason &stop_reason) {
        std::string message;
        switch (stop_reason.reason) {
        case zdb::ProcessState::Terminated:
            message = fmt::format("terminated with status {}", static_cast<int>(stop_reason.info));
            break;
        case zdb::ProcessState::Exited:
            message = fmt::format("exited with status {}", static_cast<int>(stop_reason.info));
            break;
        case zdb::ProcessState::Stopped:
            message = fmt::format(
                "stopped with signal {} at {:#x}", 
                sigabbrev_np(stop_reason.info), 
                process.get_pc().addr()
            );
            break;
        }
        fmt::print("Process {} {}\n", process.pid(), message);
    }

    void print_help(const std::vector<std::string> &args) {
        if (args.size() == 1) {
            std::cerr << R"(Available commands:
                breakpoint - Commands for operating on breakpoints
                continue - Resume the process
                register - Commands for operating on registers
                memory - Commands for operating on memory
                step - Step over a single instruction)" << std::endl;
        } else if (args[1] == "register") {
            std::cerr << R"(Available commands:
            read
            read <register>
            read all
            write <register> <value>)" << std::endl;
        } else if (args[1] == "breakpoint") {
            std::cerr << R"(Available commands:
            list
            set <address>
            enable <id>
            disable <id>
            delete <id>)" << std::endl;
        } else if (is_prefix(args[1], "memory")) {
            std::cerr << R"(Available commands:
            read <address>
            read <address> <number of bytes>
            write <address> <bytes>
            )";
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

    void handle_register_command(zdb::Process &process, const std::vector<std::string> &args) {
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

    void handle_breakpoint_list_command(zdb::Process &process) {
        if (process.breakpoint_sites().empty()) {
            fmt::print("No breakpoints set\n");
            return;
        }

        fmt::print("Current Breakpoints:\n");
        process.breakpoint_sites().for_each(
            [&](auto &site) {
                fmt::print("{}: address = {:#x}, enabled = {}\n", 
                    site->id(), 
                    site->address().addr(), 
                    site->is_enabled() ? "enabled" : "disabled"
                );
            }
        );
    }

    void handle_breakpoint_set_command(zdb::Process &process, const std::string &sub_cmd_arg) {
        auto address = zdb::to_integral<std::uint64_t>(sub_cmd_arg, 16);

        if (!address) {
            fmt::print(
                stderr,
                "Breakpoint command expects address in hexadecimal, prefixed with '0x'\n"
            );
            return;
        }

        process.create_breakpoint_site(zdb::VirtualAddr(address.value())).enable();
        fmt::print("Breakpoint set at {:#x}\n", address.value());
    }

    void handle_breakpoint_command(zdb::Process &process, const std::vector<std::string> &args) {
        if (args.size() < 2) {
            print_help({"help", "breakpoint"});
            return;
        }

        auto sub_command = args[1];
        if (is_prefix(sub_command, "list")) {
            handle_breakpoint_list_command(process);
            return;
        } 
        
        if (args.size() < 3) {
            print_help({"help", "breakpoint"});
            return;
        }
        if (is_prefix(sub_command, "set")) {
            handle_breakpoint_set_command(process, args[2]);
            return;
        } 

        auto bp_id = zdb::to_integral<std::uint64_t>(args[2], 10);
        if (!bp_id) {
            fmt::print(
                stderr,
                "Breakpoint command expects breakpoint id\n"
            );
            return;
        }

        if (is_prefix(sub_command, "enable")) {
            process.breakpoint_sites().get_by_id(bp_id.value()).enable();
        } else if (is_prefix(sub_command, "disable")) {
            process.breakpoint_sites().get_by_id(bp_id.value()).disable();
        } else if (is_prefix(sub_command, "delete")) {
            process.breakpoint_sites().remove_by_id(bp_id.value());
        } 
    }

    /// memory read addr size
    void handle_memory_read_command(zdb::Process &process, const std::vector<std::string> &args) { 
        auto address = zdb::to_integral<std::uint64_t>(args[2], 16);
        if (!address) {
            zdb::Error::send("Invalid address format");
        }
        auto n_bytes = 32;
        if (args.size() == 4) {
            auto bytes_arg = zdb::to_integral<std::size_t>(args[3]);
            if (!bytes_arg) {
                zdb::Error::send("Invalid number of bytes");
            }
            n_bytes = bytes_arg.value();
        }
        auto data = process.read_memory(zdb::VirtualAddr{address.value()}, n_bytes);
        for (std::size_t i = 0; i < data.size(); i += 16) {
            auto start = data.begin() + i;
            auto end = data.begin() + std::min(i + 16, data.size());
            fmt::print("{:#016x}: {:02x}\n", address.value() + i, fmt::join(start, end, " "));
        }
    }

    void handle_memory_write_command(zdb::Process &process, const std::vector<std::string> &args) { 
        if (args.size() != 4) {
            print_help({"memory", "help"});
            return;
        }

        auto address = zdb::to_integral<std::uint64_t>(args[2], 16);
        if (!address) {
            zdb::Error::send("Invalid address format");
        }
        auto data = zdb::parse_vector(args[3]);
        process.write_memory(zdb::VirtualAddr{address.value()}, { data.data(), data.size() });
    }

    void handle_memory_command(zdb::Process &process, const std::vector<std::string> &args) {
        if (args.size() < 3) {
            print_help({"memory", "help"});
            return;
        }

        if (is_prefix(args[1], "read")) {
            handle_memory_read_command(process, args);
        } else if (is_prefix(args[1], "write")) {
            handle_memory_write_command(process, args);
        } else {
            print_help({"memory", "help"});
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
        } else if (is_prefix(command, "breakpoint")) {
            handle_breakpoint_command(*process, args);
        } else if (is_prefix(command, "step")) {
            auto stop_reason = process->step();
            print_stop_reason(*process, stop_reason);
        } else if (is_prefix(command, "memory")) {
            handle_memory_command(*process, args);
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
