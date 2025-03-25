#include <editline/readline.h>
#include <libzdb/error.hpp>
#include <libzdb/process.hpp>
#include <string.h>
#include <vector>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <libzdb/parse.hpp>
#include <libzdb/disassembler.hpp>

namespace {
    zdb::Process *g_zdb_process = nullptr;
    void handle_sigint(int) {
        kill(g_zdb_process->pid(), SIGSTOP);
    }
}


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
    //555555555000 
    // func addr 11c9
    std::string get_sigtrap_info(const zdb::Process& process, zdb::StopReason reason) {
        if (reason.trap_type == zdb::TrapType::SoftwareBreakpoint) {
            auto& site = process.breakpoint_sites().get_by_address(process.get_pc());
            return fmt::format(" (breakpoint {})", site.id());
        } else if (reason.trap_type == zdb::TrapType::HardwareBreakpoint) {
            auto id = process.get_lastest_hardward_stoppoint_id();
            if (id.index() == 0) {
                return fmt::format(" (breakpoint {})",  std::get<0>(id));
            }

            std::string msg = "";
            auto &wp = process.watchpoints().get_by_id(std::get<1>(id));
            msg += fmt::format(" (watchpoint {})", wp.id());
            if (wp.data() == wp.previous_data()) {
                msg += fmt::format("\nValue: {:#x}", wp.data());
            } else {
                msg += fmt::format("\nOld value: {:#x}\nNew value: {:#x}", wp.previous_data(), wp.data());
            }
            return msg;
        } else if (reason.trap_type == zdb::TrapType::SignalStep) {
            return " (single step)";
        }
        return "";
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
            if (stop_reason.info == SIGTRAP) {
                message += get_sigtrap_info(process, stop_reason);
            }
            break;
        }
        fmt::print("Process {} {}\n", process.pid(), message);
    }

    void print_help(const std::vector<std::string> &args) {
        if (args.size() == 1) {
            std::cerr << R"(Available commands:
                disassemble - Disassemble machine code to assembly
                breakpoint  - Commands for operating on breakpoints
                watchpoint  - Commands for operating on watchpoints
                continue    - Resume the process
                register    - Commands for operating on registers
                memory      - Commands for operating on memory
                step        - Step over a single instruction)" << std::endl;
        } else if (args[1] == "register") {
            std::cerr << R"(Available commands:
            read
            read <register>
            read all
            write <register> <value>)" << std::endl;
        } else if (args[1] == "breakpoint") {
            std::cerr << R"(Available commands:
            list
            set <address> [-h]
            enable <id>
            disable <id>
            delete <id>)" << std::endl;
        } else if (is_prefix(args[1], "memory")) {
            std::cerr << R"(Available commands:
            read <address>
            read <address> <number of bytes>
            write <address> <bytes>)" << std::endl;
        } else if (is_prefix(args[1], "disassemble")) {
            std::cerr << R"(Available options:
            -c <number of instructions>
            -a <start address>
            )";
        } else if (is_prefix(args[1], "watchpoint")) {
            std::cerr << R"(Available commands:
            list
            delete <id>
            disable <id>
            enable <id>
            set <address> <write|rw|execute> <size>)" << std::endl;
        }else {
            std::cerr << "No help available on that\n";
        }
    }

    void print_disassembly(zdb::Process &process, zdb::VirtualAddr addr, std::size_t n_instructions) {
        auto dis = zdb::Disassembler(process);
        auto instructions = dis.disassemble(n_instructions, addr);
        for (auto instr : instructions) {
            fmt::print("{:#018x}: {}\n", instr.address.addr(), instr.text);
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
                if (site->is_internal()) return;
                fmt::print("{}: address = {:#x}, enabled = {}\n", 
                    site->id(), 
                    site->address().addr(), 
                    site->is_enabled() ? "enabled" : "disabled"
                );
            }
        );
    }

    void handle_breakpoint_set_command(zdb::Process &process, const std::vector<std::string> &args) {
        auto address = zdb::to_integral<std::uint64_t>(args[2], 16);
        if (!address) {
            fmt::print(
                stderr,
                "Breakpoint command expects address in hexadecimal, prefixed with '0x'\n"
            );
            return;
        }

        bool is_hardware = false;
        if (args.size() == 4) {
            if (args[3] == "-h") is_hardware = true;
            else zdb::Error::send("Invalid argument");
        }

        process.create_breakpoint_site(zdb::VirtualAddr(address.value()), is_hardware = is_hardware).enable();
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
            handle_breakpoint_set_command(process, args);
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

    void handle_disassemble_command(zdb::Process &process, const std::vector<std::string> &args) {
        zdb::VirtualAddr address = process.get_pc();
        std::size_t n_instructions = 5;
        auto it = args.begin() + 1;
        while (it != args.end()) {
            if (*it == "-c" && it + 1 != args.end()) {
                ++it;
                auto opt_n =  zdb::to_integral<std::uint64_t>(*it);
                if (!opt_n) {
                    zdb::Error::send("Invalid amount format");
                }
                n_instructions = opt_n.value();
                ++it;
            } else if (*it == "-a" && it + 1 != args.end()) {
                ++it;
                auto opt_addr = zdb::to_integral<std::uint64_t>(*it);
                if (!opt_addr) {
                    zdb::Error::send("Invalid address format");
                }
                address = zdb::VirtualAddr{opt_addr.value()};
                ++it;
            } else {
                print_help({"help", "disassemble"});
                return;
            }
        }
    }

    void handle_watchpoint_list_command(zdb::Process& process, const std::vector<std::string>& args) {
        auto stoppoint_mode_to_string = [](auto mode) {
            switch (mode) {
                case zdb::StopPointMode::Execute: return "execute";
                case zdb::StopPointMode::Write: return "write";
                case zdb::StopPointMode::ReadWrite: return "read_write";
                default: zdb::Error::send("Invalid stoppoint mode");
            }
        };
        if (process.watchpoints().empty()) {
            fmt::print("No watchpoints set\n");
        }
        else {
            fmt::print("Current watchpoints:\n");
            process.watchpoints().for_each(
                [&](auto& point) {
                    fmt::print("{}: address = {:#x}, mode = {}, size = {}, {}\n",
                        point->id(), 
                        point->address().addr(),
                        stoppoint_mode_to_string(point->mode()), 
                        point->size(),
                        point->is_enabled() ? "enabled" : "disabled"
                    );
                }
            );
        }
    }

    void handle_watchpoint_set_command(zdb::Process& process, const std::vector<std::string>& args) {
        if (args.size() < 5) {
            print_help({"help", "watchpoint"});
            return;
        }
        auto addr = zdb::to_integral<std::uint64_t>(args[2], 16);
        auto mode_text = args[3];
        auto size = zdb::to_integral<std::size_t>(args[4], 10);
        if (!addr || !size || !(mode_text == "w" || mode_text == "rw" || mode_text == "exec") ) {
            print_help({"help", "watchpoint"});
        }

        zdb::StopPointMode mode;
        if (mode_text == "write") mode = zdb::StopPointMode::Write;
        else if (mode_text == "rw") mode = zdb::StopPointMode::ReadWrite;
        else if (mode_text == "execute") mode = zdb::StopPointMode::Execute;

        process.create_watchpoint(zdb::VirtualAddr(addr.value()), mode, size.value()).enable();
    }

    void handle_watchpoint_command(zdb::Process &process, const std::vector<std::string> &args) {
        // watchpoint set <address> <mode> <size>
        // watchpoint enable/disable/delete <id>
        if (args.size() < 2) {
            print_help({"help", "watchpoint"});
            return;
        }

        if (is_prefix(args[1], "list")) {
            handle_watchpoint_list_command(process, args);
            return;
        }

        if (args[1] == "set") {
            handle_watchpoint_set_command(process, args);
            return;
        }  

        if (args.size() < 3) {
            print_help({"help", "watchpoint"});
            return;
        }

        auto id_opt = zdb::to_integral<zdb::Watchpoint::id_type>(args[2], 10);
        if (!id_opt) {
            zdb::Error::send("Invalid id format");
        }
        else if (args[1] == "enable") {
            process.watchpoints().get_by_id(id_opt.value()).enable();
        } else if (args[1] == "disable") {
            process.watchpoints().get_by_id(id_opt.value()).disable();
        } else if (args[1] == "delete") {
            process.watchpoints().remove_by_id(id_opt.value());
        } else {
            print_help({"help", "watchpoint"});
        }
    }

    void handle_stop(zdb::Process &process, zdb::StopReason &stop_reason) {
        print_stop_reason(process, stop_reason);
        if (stop_reason.reason == zdb::ProcessState::Stopped) {
            print_disassembly(process, process.get_pc(), 5);
        }
    }

    /// @brief  disassemble -c <count> -a <address>
    void handle_command(std::unique_ptr<zdb::Process> &process, std::string_view line) {
        auto args    = split(line, ' ');
        auto command = args[0];
        if (is_prefix(command, "continue")) {
            process->resume();
            zdb::StopReason stop_reason = process->wait_on_signal();
            handle_stop(*process, stop_reason);
        } else if (is_prefix(command, "help")) {
            print_help(args);
        } else if (is_prefix(command, "register")) {
            handle_register_command(*process, args);
        } else if (is_prefix(command, "breakpoint")) {
            handle_breakpoint_command(*process, args);
        } else if (is_prefix(command, "step")) {
            auto stop_reason = process->step();
            handle_stop(*process, stop_reason);
        } else if (is_prefix(command, "memory")) {
            handle_memory_command(*process, args);
        } else if (is_prefix(command, "disassemble")) {
            handle_disassemble_command(*process, args);
        } else if (is_prefix(command, "watchpoint")) {
            handle_watchpoint_command(*process, args);
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
        g_zdb_process = process.get();
        signal(SIGINT, handle_sigint);
        main_loop(process);
    } catch (const zdb::Error &err) {
        std::cout << err.what() << '\n';
    }

   
}
