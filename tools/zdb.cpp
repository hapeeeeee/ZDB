#include <editline/readline.h>
#include <libzdb/error.hpp>
#include <libzdb/process.hpp>
#include <string.h>
#include <vector>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <libzdb/parse.hpp>
#include <libzdb/disassembler.hpp>
#include <libzdb/syscall.hpp>
#include <cctype>
#include <libzdb/target.hpp>
#include <libzdb/elf.hpp>
#include <fstream>
#include <filesystem>
#include <cmath>

namespace {
    zdb::Process *g_zdb_process = nullptr;
    void handle_sigint(int) {
        kill(g_zdb_process->pid(), SIGSTOP);
    }

    void thread_lifecycle_callback(const zdb::StopReason& reason) {
        std::string_view action;
        switch (reason.reason) {
            case zdb::ProcessState::Exited: { action = "exited"; break; }
            case zdb::ProcessState::Terminated: { action = "terminated"; break; }
            case zdb::ProcessState::Stopped: { action = "created"; break; }
        }
        fmt::print("Thread {} {}\n", reason.tid, action);
    }
}


namespace {
    std::unique_ptr<zdb::Target> attach(int argc, const char **argv) {
        // Passing PID
        if (argc == 3 && argv[1] == std::string_view("-p")) {
            pid_t pid = std::atoi(argv[2]);
            return zdb::Target::attach(pid);
        }
        // Passing program name
        else {
            const char *program_path = argv[1];
            auto proc = zdb::Target::launch(program_path);
            fmt::print("Process {} launched\n", proc->get_process().pid());
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

    std::string get_sigtrap_info(const zdb::Process& process, zdb::StopReason reason) {
        if (reason.trap_type == zdb::TrapType::SoftwareBreakpoint) {
            auto& site = process
                .breakpoint_sites()
                .get_by_address(process.get_pc(reason.tid));
            return fmt::format(" (breakpoint {})", site.id());
        } else if (reason.trap_type == zdb::TrapType::HardwareBreakpoint) {
            auto id = process
                .get_lastest_hardward_stoppoint_id(reason.tid);
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
        } else if (reason.trap_type == zdb::TrapType::Syscall) {
            std::string msg = "";
            zdb::SyscallInfo &info = reason.syscall_info.value();
            if (info.is_in_syscall) {
                msg += fmt::format(" (syscall entry)\n");
                msg += fmt::format(
                    "(syscall: {} ({:#x}))", 
                    zdb::syscall_id_to_name(info.syscall_id),
                    fmt::join(info.args, ",")
                );
            } else {
                msg += fmt::format(" (syscall exit)\n");
                msg += fmt::format(" (syscall: {} ({:#x}))", 
                    zdb::syscall_id_to_name(info.syscall_id),
                    info.retval
                );
            }
            return msg;
        }
        return "";
    }

    std::string get_signal_stop_reason(const zdb::Target &target, zdb::StopReason &stop_reason) {
        auto& process = target.get_process();
        auto pc = process.get_pc(stop_reason.tid);

        std::string message = fmt::format(
            "stopped with signal {} at {:#x}",
            sigabbrev_np(stop_reason.info), 
            pc.addr()
        );

        zdb::LineTable::iterator line = target.line_entry_at_pc(stop_reason.tid);
        if (line != zdb::LineTable::iterator()) {
            std::string file = line->file_entry->path.filename().string();
            message += fmt::format(", {}:{}", file, line->line);
        }

        auto func_name = target.function_name_at_address(pc);
        if (func_name != "") {
            message += fmt::format(" ({})", func_name);
        }

        if (stop_reason.info == SIGTRAP) {
            message += get_sigtrap_info(process, stop_reason);
        }

        return message;
    }

    void print_stop_reason(const zdb::Target &target, zdb::StopReason &stop_reason) {
        std::string message;
        switch (stop_reason.reason) {
        case zdb::ProcessState::Terminated:
            fmt::print(
                "Process {} terminated with status {}", 
                target.get_process().pid(),
                sigabbrev_np(stop_reason.info)
            );
            return ;
        case zdb::ProcessState::Exited:
            fmt::print(
                "Process {} exited with status {}", 
                target.get_process().pid(),
                static_cast<int>(stop_reason.info));
            return ;
        case zdb::ProcessState::Stopped:
            fmt::print(
                "Thread {} {}\n",
                stop_reason.tid, 
                get_signal_stop_reason(target, stop_reason)
            );
            return;
        }
    }

    void print_help(const std::vector<std::string> &args) {
        if (args.size() == 1) {
            std::cerr << R"(Available commands:
                disassemble - Disassemble machine code to assembly
                breakpoint  - Commands for operating on breakpoints
                watchpoint  - Commands for operating on watchpoints
                catchpoint  - Commands for operating on catchpoints
                variable    - Commands for operating on variables
                continue    - Resume the process
                register    - Commands for operating on registers
                memory      - Commands for operating on memory
                thread      - Commands for operating on threads
                step        - Step-in
                next        - Step-over
                finish      - Step-out
                stepi       - Single instruction step
                down        - Select the stack frame below the current one
                up          - Select the stack frame above the current one)" << std::endl;
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
        } else if (is_prefix(args[1], "catchpoint")) {
            std::cerr << R"(Available commands:
            syscall
            syscall none
            syscall <list of syscall IDs or names>)" << std::endl;
        } else if (is_prefix(args[1], "variable")) {
            std::cerr << R"(Available commands:
            read <variable>)" << std::endl;
        } else if (is_prefix(args[1], "thread")) {
            std::cerr << R"(Available commands:
                list
                select <thread ID>)" << std::endl;
        } else {
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

    void handle_register_read_command(const zdb::Target &target, const std::vector<std::string> &args) {
        auto fn_format = [](auto t) -> std::string {
            if constexpr (std::is_floating_point_v<decltype(t)>) {
                return fmt::format("{}", t);
            } else if constexpr (std::is_integral_v<decltype(t)>) {
                return fmt::format("{:#0{}x}", t, sizeof(t) * 2 + 2);
            } else {
                return fmt::format("[{:#04x}]", fmt::join(t, ","));
            }
        };

        const zdb::Registers& regs = target.get_stack().regs();
        auto print_register_value = [&](auto info) {
            if (regs.is_undefined(info.id)) {
                fmt::print("{}:\tundefined\n", info.name);
            }
            else {
                auto value = regs.read(info);
                fmt::print("{}:\t{}\n", info.name, std::visit(fn_format, value));
            }
        };
        
        if (args.size() == 2                        ///< register read
            || args.size() == 3 && args[2] == "all" ///< register read all
        ) {
            for (auto reg_info : zdb::g_register_infos) {
                bool should_print = 
                    (reg_info.type == zdb::RegisterType::gpr && reg_info.name != "orig_rax");
                if (!should_print) continue;
                print_register_value(reg_info);
            }
        }
        else if (args.size() == 3) {             ///< register read <register>
            try {
                auto reg_info = zdb::find_register_info_by_name(args[2]);
                print_register_value(reg_info);
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

    void handle_register_command(zdb::Target &target, const std::vector<std::string> &args) {
        if (args.size() < 2) {
            print_help({"help", "register"});
            return;
        } 
        
        if (args[1] == "read") {
            handle_register_read_command(target, args);
        } else if (args[1] == "write") {
            handle_register_write_command(target.get_process(), args);
        } else {
            print_help({"help", "register"});
        }
    }

    void handle_breakpoint_list_command(zdb::Target& target) {
        if (target.breakpoints().empty()) {
            fmt::print("No breakpoints set\n");
            return;
        }

        fmt::print("Current Breakpoints:\n");
        target.breakpoints().for_each(
            [&](auto &bp) {
                if (bp->is_internal()) return;
                fmt::print("{}: ", bp->id());
                if (auto func_bp = dynamic_cast<zdb::FunctionBreakpoint*>(bp.get())) {
                    fmt::print("function = {}", func_bp->function_name());
                } else if (auto line_bp = dynamic_cast<zdb::LineBreakpoint*>(bp.get())) {
                    fmt::print("file = {}, line = {}",
                        line_bp->file().string(), 
                        line_bp->line()
                    );
                } else if (auto addr_bp = dynamic_cast<zdb::AddressBreakpoint*>(bp.get())) {
                    fmt::print("address = {:#x}", addr_bp->address().addr());
                }
                fmt::print(", {}:\n", bp->is_enabled() ? "enabled" : "disabled");
                bp->breakpoint_sites().for_each(
                    [&](auto& site) {
                        fmt::print(" .{}: address = {:#x}, {}\n",
                            site->id(), 
                            site->address().addr(),
                            site->is_enabled() ? "enabled" : "disabled"
                        );
                    }
                );
            }
        );
    }

    void handle_breakpoint_set_command(zdb::Target &target, const std::vector<std::string> &args) {
        bool is_hardware = false;
        if (args.size() == 4) {
            if (args[3] == "-h") is_hardware = true;
            else zdb::Error::send("Invalid argument");
        }

        if (args[2].find("0x") == 0) {
            std::optional<std::uint64_t> address = zdb::to_integral<std::uint64_t>(args[2], 16);
            if (!address) {
                fmt::print(
                    stderr,
                    "Breakpoint command expects address in hexadecimal, prefixed with '0x'\n"
                );
                return;
            }
            target.create_address_breakpoint(
                zdb::VirtualAddr{ *address }, 
                false, 
                is_hardware
            ).enable();
        } 
        else if (args[2].find(':') != std::string::npos) {
            std::vector<std::string> data = split(args[2], ':');
            std::string path = data[0];
            std::optional<std::uint64_t> line = zdb::to_integral<std::uint64_t>(data[1]);
            if (!line) {
                fmt::print(
                    stderr,
                    "Line number should be an integer\n"
                );
                return;
            }
            target.create_line_breakpoint(
                path, 
                *line, 
                false, 
                is_hardware
            ).enable();
        }
        else {
            target.create_function_breakpoint(args[2]).enable();
        }

    }

    void handle_breakpoint_toggle(zdb::Target& target, const std::vector<std::string>& args) {
        std::string sub_command = args[1]; // enable/disable
        std::string bp_id_with_site_id = args[2]; // bp enbale 1.2

        std::size_t dot_pos = bp_id_with_site_id.find('.');
        std::string id_str = args[2].substr(0, dot_pos);
        std::optional<int> id = zdb::to_integral<zdb::Breakpoint::id_type>(id_str);
        if (!id) {
            std::cerr << "Command expects breakpoint id";
            return;
        }

        zdb::Breakpoint& bp = target.breakpoints().get_by_id(*id);
        if (dot_pos != std::string::npos) {
            std::string site_id_str = bp_id_with_site_id.substr(dot_pos + 1);
            std::optional<int> site_id = zdb::to_integral<zdb::BreakpointSite::id_type>(site_id_str);
            if (!site_id) {
                std::cerr << "Command expects breakpoint site id";
                return;
            }

            if (is_prefix(sub_command, "enable")) {
                bp.breakpoint_sites().get_by_id(*site_id).enable();
            }
            else if (is_prefix(sub_command, "disable")) {
                bp.breakpoint_sites().get_by_id(*site_id).disable();
            }
        }
        else if (is_prefix(sub_command, "enable")) {
            bp.enable();
        }
        else if (is_prefix(sub_command, "disable")) {
            bp.disable();
        }
        else if (is_prefix(sub_command, "delete")) {
            bp.breakpoint_sites().for_each(
                [&](auto& site) {
                    target.get_process()
                        .breakpoint_sites()
                        .remove_by_address(site->address());
                }   
            );
            target.breakpoints().remove_by_id(*id);
        }
    }

    void handle_breakpoint_command(zdb::Target& target, const std::vector<std::string>& args) {
        if (args.size() < 2) {
            print_help({"help", "breakpoint"});
            return;
        }

        auto sub_command = args[1];
        if (is_prefix(sub_command, "list")) {
            handle_breakpoint_list_command(target);
            return;
        } 
        
        if (args.size() < 3) {
            print_help({"help", "breakpoint"});
            return;
        }
        if (is_prefix(sub_command, "set")) {    
            handle_breakpoint_set_command(target, args);
            return;
        } 

        handle_breakpoint_toggle(target, args);

        // auto bp_id = zdb::to_integral<std::uint64_t>(args[2], 10);
        // if (!bp_id) {
        //     fmt::print(
        //         stderr,
        //         "Breakpoint command expects breakpoint id\n"
        //     );
        //     return;
        // }

        // if (is_prefix(sub_command, "enable")) {
        //     process.breakpoint_sites().get_by_id(bp_id.value()).enable();
        // } else if (is_prefix(sub_command, "disable")) {
        //     process.breakpoint_sites().get_by_id(bp_id.value()).disable();
        // } else if (is_prefix(sub_command, "delete")) {
        //     process.breakpoint_sites().remove_by_id(bp_id.value());
        // } 
    }

    void handle_thread_command(zdb::Target& target, const std::vector<std::string>& args) {
        if (args.size() < 2) {
            print_help({ "help", "thread" });
            return;
        }

        if (is_prefix(args[1], "list")) {
            for (auto& [tid, thread] : target.get_threads()) {
                auto prefix = tid == target.get_process().current_thread() ? "*" : " ";
                fmt::print(
                    "{}Thread {}: {}\n",
                    prefix,
                    tid,
                    get_signal_stop_reason(target, thread.state->reason)
                );
            }
        } else if (is_prefix(args[1], "select")) {
            if (args.size() != 3) {
                print_help({ "help", "thread" });
                return;
            }
            auto tid = zdb::to_integral<pid_t>(args[2]);
            if (!tid) {
                std::cerr << "Invalid thread id\n";
                return;
            }
            target.get_process().set_current_thread(*tid);
        }
    }

    void handle_variable_command(zdb::Target& target, const std::vector<std::string>& args) {
        if (args.size() < 3) {
            print_help({ "help", "variable" });
            return;
        }

        if (is_prefix(args[1], "read")) {
            auto die = target.get_main_elf().get_dwarf().find_global_variable(args[2]);
            auto loc = die
                .value()[DW_AT_location]
                .as_evaluated_location(
                    target.get_process(), 
                    target.get_stack().current_frame().regs, 
                    false);

            auto value = target.read_location_data(loc, 8);
            std::uint64_t res = 0;
            std::copy(value.begin(), value.end(), reinterpret_cast<std::byte*>(&res));
            std::cout << "Value: " << res << '\n';
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

    void handle_catchpoint_syscall_command(zdb::Process &process, const std::vector<std::string> &args) {
        zdb::SyscallCatchPolicy policy = zdb::SyscallCatchPolicy::catch_all();
        if (args.size() == 3 && args[2] == "none") {
            policy = zdb::SyscallCatchPolicy::catch_none();
        } else if (args.size() >= 3) {
            std::vector<std::string> name_or_id_of_syscalls = split(args[2], ',');
            std::vector<int> to_catch_ids;
            std::transform(
                name_or_id_of_syscalls.begin(), 
                name_or_id_of_syscalls.end(),
                std::back_inserter(to_catch_ids),
                [](auto &syscall) {
                    return std::isdigit(syscall[0])?
                        zdb::to_integral<int>(syscall, 10).value():
                        zdb::syscall_name_to_id(syscall);
                }
            );
            policy = zdb::SyscallCatchPolicy::catch_some(std::move(to_catch_ids));
        }
        process.set_syscall_catch_policy(std::move(policy));
    }

    void handle_catchpoint_command(zdb::Process &process, const std::vector<std::string> &args) {
        zdb::SyscallCatchPolicy policy = zdb::SyscallCatchPolicy::catch_all();
        if (args.size() < 2) { 
            print_help({"help", "catchpoint"});
            return;
        }

        if (is_prefix(args[1], "syscall")) {
            handle_catchpoint_syscall_command(process, args);
            return;
        }
    }

    void print_backtrace(const zdb::Target& target) {
        const zdb::Stack& stack = target.get_stack();
        int i = 0;
        for (const zdb::StackFrame& frame : stack.frames()) {
            zdb::VirtualAddr pc = frame.backtrace_report_address;
            std::string func_name = target.function_name_at_address(pc);
            std::string message = i == stack.current_frame_index() ? "*" : " ";
            message += fmt::format("[{}]: {:#x} {}", i++, pc.addr(), func_name);
            if (frame.inlined) {
                message += fmt::format(" [inlined] {}", *frame.func_die.name());
            }
            fmt::print("{}\n", message);
        }
    }

    void print_source(
        const std::filesystem::path& path, 
        std::uint64_t line,
        std::uint64_t n_lines_context
    ) {
        std::ifstream file{ path.string() };
        auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
        auto end_line = line + n_lines_context + 1;
        
        char c{};
        auto current_line = 1u;
        while (current_line != start_line && file.get(c)) {
            if (c == '\n') {
                ++current_line;
            }
        }

        auto print_line_start = [&](auto current_line) {
            auto fill_width = static_cast<int>(std::floor(std::log10(end_line))) + 1;
            auto arrow = current_line == line ? ">" : " ";
            fmt::print("{} {:>{}} ", arrow, current_line, fill_width);
        };

        print_line_start(current_line);
        while (current_line <= end_line && file.get(c)) {
            std::cout << c;
            if (c == '\n') {
                ++current_line;
                print_line_start(current_line);
            }
        }
        std::cout << std::endl;

    }

    void print_code_location(zdb::Target &target) {
       if (target.get_stack().has_frames()) {
            const zdb::StackFrame& frame = target.get_stack().current_frame();
            print_source(frame.location.file->path, frame.location.line, 3);
        }
        else if (
            auto entry = target.line_entry_at_pc();
            entry != zdb::LineTable::iterator()
        ) {
            print_source(entry->file_entry->path, entry->line, 3);
        } 
        else {
            print_disassembly(
                target.get_process(), 
                target.get_process().get_pc(), 
                5
            );
        }
    }

    void handle_stop(zdb::Target &target, zdb::StopReason &stop_reason) {
        print_stop_reason(target, stop_reason);
        if (stop_reason.reason == zdb::ProcessState::Stopped) {
            print_code_location(target);
        }
    }

    /// @brief  disassemble -c <count> -a <address>
    void handle_command(std::unique_ptr<zdb::Target> &target, std::string_view line) {
        auto process = &target->get_process();
        auto args    = split(line, ' ');
        auto command = args[0];
        if (is_prefix(command, "continue")) {
            process->resume_all_threads();
            zdb::StopReason stop_reason = process->wait_on_signal();
            handle_stop(*target, stop_reason);
        } else if (is_prefix(command, "help")) {
            print_help(args);
        } else if (is_prefix(command, "register")) {
            handle_register_command(*target, args);
        } else if (is_prefix(command, "breakpoint")) {
            handle_breakpoint_command(*target, args);
        } else if (is_prefix(command, "thread")) {
            handle_thread_command(*target, args);
        } else if (is_prefix(command, "variable")) {
            handle_variable_command(*target, args);
        } else if (is_prefix(command, "step")) {
            auto reason = target->step_in();
            handle_stop(*target, reason);
        } else if (is_prefix(command, "stepi")) {
            auto stop_reason = process->step();
            handle_stop(*target, stop_reason);
        } else if (is_prefix(command, "next")) {
            auto reason = target->step_over();
            handle_stop(*target, reason);
        } else if (is_prefix(command, "finish")) {
            auto reason = target->step_out();
            handle_stop(*target, reason);
        } else if (is_prefix(command, "memory")) {
            handle_memory_command(*process, args);
        } else if (is_prefix(command, "disassemble")) {
            handle_disassemble_command(*process, args);
        } else if (is_prefix(command, "watchpoint")) {
            handle_watchpoint_command(*process, args);
        } else if (is_prefix(command, "catchpoint")) {
            handle_catchpoint_command(*process, args);
        } else if (is_prefix(command, "backtrace")) { 
            print_backtrace(*target);
        }else if (is_prefix(command, "up")) {
            target->get_stack().up();
            print_code_location(*target);
        } else if (is_prefix(command, "down")) {
            target->get_stack().down();
            print_code_location(*target);
        } else {
            std::cerr << "Unknown command\n";
        }
    }

    void main_loop(std::unique_ptr<zdb::Target> &target) {
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
                    handle_command(target, line_string);
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
        auto target = attach(argc, argv);
        g_zdb_process = &(target->get_process());
        signal(SIGINT, handle_sigint);
        target->get_process()
            .install_thread_lifecycle_callback(thread_lifecycle_callback);

        main_loop(target);
    } catch (const zdb::Error &err) {
        std::cout << err.what() << '\n';
    }
}
