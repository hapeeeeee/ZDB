#include <libzdb/target.hpp>
#include <libzdb/type.hpp>
#include <libzdb/elf.hpp>
#include <libzdb/parse.hpp>
#include <optional>
#include <libzdb/disassembler.hpp>
#include <cxxabi.h>
#include <fstream>
#include <iostream>
namespace {
    // 用户能够在计算表达式后引用带有编号变量的返回值，如$0和$1。返回值的内存必须在
    // 调试会话的剩余时间内保持不变。 因此此处需要动态分配内存（堆上）。
    // 如果返回值确实具有MEMORY类，则计算器将传递一个指针，指向已分配好的存储内存地址
    // 否则，返回值存储在寄存器中，
    // read_return_value的工作是将数据复制到分配的存储中，以便用户以后可以访问它。
    zdb::TypedData read_return_value(
        zdb::Target& target,            // 调试目标（包含进程等信息）
        zdb::DIE func,                  // 表示当前函数的调试信息
        zdb::VirtualAddr return_slot,   // 返回值要存放的地址
        zdb::Registers& regs            // 当前函数返回后的寄存器快照
    ) {
        auto ret_type = func[DW_AT_type].as_type();
        auto ret_classes = ret_type.get_parameter_classes();

        bool used_int = false;
        bool used_sse = false;

        // 如果返回类型是内存参数，则返回值已经在内存中，直接读出打包返回
        if (ret_classes[0] == zdb::ParameterClass::memory) {
            auto value = target.get_process().read_memory(
                return_slot, 
                ret_type.byte_size()
            );
            return { 
                std::move(value), 
                func[DW_AT_type].as_type(), 
                return_slot 
            };
        }

        // 如果是long double，读取浮点寄存器，写入内存，再打包返回
        if (ret_classes[0] == zdb::ParameterClass::x87) {
            auto data = regs.read_by_id_as<long double>(zdb::RegisterId::st0);
            auto value = zdb::to_byte_vec(data);
            target.get_process().write_memory(return_slot, value);
            return {
                std::move(value), 
                func[DW_AT_type].as_type(), 
                return_slot 
            };
        }

        std::vector<std::byte> value;
        for (auto &ret_class : ret_classes) {
            if (ret_class == zdb::ParameterClass::integer) {
                // 第一个 integer 类型的返回值来自 rax，第二个来自 rdx（System V ABI）。
                auto reg = used_int ? 
                    zdb::RegisterId::rdx: 
                    zdb::RegisterId::rax;
                used_int = true;
                std::uint64_t data = regs.read_by_id_as<std::uint64_t>(reg);
                auto new_value = zdb::to_byte_vec(data);
                value.insert(value.end(), new_value.begin(), new_value.end());
            }
            else if (ret_class == zdb::ParameterClass::sse) {
                auto reg = used_sse ? 
                    zdb::RegisterId::xmm1: 
                    zdb::RegisterId::xmm0;
                used_sse = true;
                auto data = regs.read_by_id_as<zdb::byte128>(reg);
                value = { data.begin(), data.end() };
                target.get_process().write_memory(return_slot, value);

            }
            else if (ret_class != zdb::ParameterClass::no_class) {
                zdb::Error::send("Unsupported return type");
            }
        }

        target.get_process().write_memory(return_slot, value);
        return {
            std::move(value), 
            func[DW_AT_type].as_type(), 
            return_slot 
        };
    }

    void setup_arguments(
        zdb::Target& target, 
        zdb::DIE func,
        std::vector<zdb::TypedData> args,
        zdb::Registers& regs,
        std::optional<zdb::VirtualAddr> return_slot // 函数的返回地址
    ) {
        std::array<zdb::RegisterId, 6> int_regs = {
            zdb::RegisterId::rdi,
            zdb::RegisterId::rsi,
            zdb::RegisterId::rdx,
            zdb::RegisterId::rcx,
            zdb::RegisterId::r8,
            zdb::RegisterId::r9
        };

        std::array<zdb::RegisterId, 8> sse_regs = {
            zdb::RegisterId::xmm0,
            zdb::RegisterId::xmm1,
            zdb::RegisterId::xmm2,
            zdb::RegisterId::xmm3,
            zdb::RegisterId::xmm4,
            zdb::RegisterId::xmm5,
            zdb::RegisterId::xmm6,
            zdb::RegisterId::xmm7
        };

        int current_int_reg = 0;
        int current_sse_reg = 0;
        struct stack_arg {
            zdb::TypedData data;
            std::size_t size;
        };
        auto stack_args = std::vector<stack_arg>{};
        std::uint64_t rsp = regs.read_by_id_as<std::uint64_t>(zdb::RegisterId::rsp);
        auto round_up_to_eightbyte = [](std::size_t size) {
            return (size + 7) & ~7;
        };

        if (func.contains(DW_AT_type)) {
            auto ret_type = func[DW_AT_type].as_type();
            auto ret_class = ret_type.get_parameter_classes()[0];
            // 提前分配内存，并把内存地址放进第一个整数寄存器里。
            if (ret_class == zdb::ParameterClass::memory) {
                current_int_reg++;
                regs.write_by_id(int_regs[0], return_slot->addr(), true);
            }
        }

        auto params = func.parameter_types();
        for (auto i = 0; i < params.size(); ++i) {
            zdb::Type& param = params[i];
            auto param_classes = param.get_parameter_classes();
            // 如果是引用类型，就需要传地址给函数，而不是传值。
            if (param.is_reference_type()) {
                if (args[i].address()) {
                    // 如果参数已经有地址（说明它在内存中），直接取地址作为参数
                    args[i] = zdb::TypedData {
                        zdb::to_byte_vec(*args[i].address()),
                        zdb::BuiltinType::integer 
                    };
                }
                else {
                    // 否则我们得手动把值拷贝到栈上，再传这个拷贝的地址
                    rsp -= args[i].value_type().byte_size();
                    rsp &= ~(args[i].value_type().alignment() - 1); // 对齐
                    target.get_process().write_memory(
                        zdb::VirtualAddr{ rsp }, args[i].data()
                    );

                    args[i] = zdb::TypedData{
                        zdb::to_byte_vec(rsp),
                        zdb::BuiltinType::integer 
                    };
                }

            }
        }


        // 分配参数到堆栈和寄存器
        for (auto i = 0; i < params.size(); ++i) {
            zdb::TypedData& arg = args[i];
            zdb::Type& param = params[i];
            auto param_classes = param.get_parameter_classes();
            std::size_t param_size = param.byte_size();

            auto required_int_regs = std::count(
                param_classes.begin(), 
                param_classes.end(),
                zdb::ParameterClass::integer
            );
            auto required_sse_regs = std::count(
                param_classes.begin(), 
                param_classes.end(),
                zdb::ParameterClass::sse
            );
            // 如果有任意一个寄存器数量不够，或者根本不使用寄存器，把参数放到栈上。
            if (current_int_reg + required_int_regs > int_regs.size()
                || current_sse_reg + required_sse_regs > sse_regs.size()
                || (required_int_regs == 0 && required_sse_regs == 0)
            ) {
                auto size = round_up_to_eightbyte(param_size);
                stack_args.push_back({ args[i], size });
            }
            else {
                // 使用寄存器传参，八字节一组
                for (auto i = 0; i < param_size; i += 8) {
                    zdb::RegisterId reg;
                    switch (param_classes[i / 8]) {
                        case zdb::ParameterClass::integer:
                            reg = int_regs[current_int_reg++];
                            break;
                        case zdb::ParameterClass::sse:
                            reg = sse_regs[current_sse_reg++];
                            break;
                        case zdb::ParameterClass::no_class:
                            break;
                        default:
                            zdb::Error::send("Unsupported parameter class");
                    }

                    zdb::byte64 data;
                    std::copy(
                        arg.data().begin() + i,
                        arg.data().begin() + i + 8,
                        data.begin()
                    );
                    regs.write_by_id(reg, data, true);

                }
            }
        }

        for (auto& [_,size] : stack_args) {
            rsp -= size;
        }
        rsp &= ~0xf; // SYSV ABI要求堆栈参数末尾的地址与16字节边界对齐
        uint64_t start_pos = rsp;

        for (auto& [arg,size] : stack_args) {
            target.get_process().write_memory(
                zdb::VirtualAddr{ start_pos }, 
                arg.data()
            );
            start_pos += size;
        }

        regs.write_by_id(zdb::RegisterId::rax, current_sse_reg, true);
        regs.write_by_id(zdb::RegisterId::rsp, rsp, true);
    } 

    zdb::TypedData parse_single_augment(
        zdb::Target& target, 
        pid_t tid, 
        std::string_view arg
    ) {
        if (arg.empty()) {
            zdb::Error::send("Empty augment");
        }

        if (arg.size() > 2 && arg[0] == '"' && arg[arg.size() - 1] == '"') {
            auto ptr = target.inferior_malloc(arg.size() - 1);
            std::string arg_str{ arg.substr(1, arg.size() - 2) };
            auto data_ptr = reinterpret_cast<const std::byte*>(arg_str.data());
            zdb::Span<const std::byte> data = { data_ptr, arg_str.size() + 1 };
            target.get_process().write_memory(ptr, data);
            return { zdb::to_byte_vec(ptr), zdb::BuiltinType::string };
        } 
        else if (arg == "true" || arg == "false") {
            auto value = arg == "true";
            return { zdb::to_byte_vec(value), zdb::BuiltinType::boolean };
        }
        else if (arg[0] == '\'') {
            if (arg.size() != 3 || arg[2] != '\'') {
                zdb::Error::send("Invalid character literal");
            }
            return { zdb::to_byte_vec(arg[1]), zdb::BuiltinType::character };
        }
        else if (arg[0] == '-' || std::isdigit(arg[0])) {
            if (arg.find(".") != std::string::npos) {
                auto value = zdb::to_float<double>(arg);
                if (!value) {
                    zdb::Error::send("Invalid floating point literal");
                }
                return { zdb::to_byte_vec(*value), zdb::BuiltinType::floating_point };
            } else {
                auto value = zdb::to_integral<std::uint64_t>(arg);
                if (!value) {
                    zdb::Error::send("Invalid Integer literal");
                }
                return { zdb::to_byte_vec(*value), zdb::BuiltinType::integer };
            }
        }
        else {
            auto pc = target.get_pc_file_address(tid);
            auto res = target.resolve_indirect_name(std::string(arg), pc);
            if (!res.funcs.empty()) {
                zdb::Error::send("Nested function calls not supported");
            }
            return *res.variable;
        }
    }

    std::optional<zdb::TypedData> inferior_call_from_dwarf(
        zdb::Target& target, 
        zdb::DIE func,
        const std::vector<zdb::TypedData>& args,
        zdb::VirtualAddr return_addr, 
        pid_t tid
    ) {
        auto& regs = target.get_process().get_registers(tid);
        auto saved_regs = regs;

        zdb::VirtualAddr call_addr;
        if (func.contains(DW_AT_low_pc) || func.contains(DW_AT_ranges)) {
            call_addr = func.low_pc().to_virt_addr();
        }
        else {
            auto def = func
                .cu()
                ->dwarf_info()
                ->get_member_function_definition(func);
            if (!def) {
                zdb::Error::send("No function definition found");
            }
            call_addr = def->low_pc().to_virt_addr();
        }

        // 为函数返回值分配空间
        std::optional<zdb::VirtualAddr> return_slot;
        if (func.contains(DW_AT_type)) {
            auto ret_type = func[DW_AT_type].as_type();
            return_slot = target.inferior_malloc(ret_type.byte_size());
        }

        setup_arguments(target, func, args, regs, return_slot);
        auto new_regs = target.get_process().inferior_call(
            call_addr, 
            return_addr, 
            saved_regs, 
            tid
        );

        if (func.contains(DW_AT_type)) {
            return read_return_value(
                target, 
                func, 
                *return_slot, 
                new_regs
            );
        }
        return std::nullopt;
    }

    std::vector<zdb::TypedData> collect_arguments(
        zdb::Target& target, 
        pid_t tid, 
        std::string_view arg_string,
        const std::vector<zdb::DIE>& funcs,
        std::optional<zdb::TypedData> object // this指针
    ) {
        // 一个函数是成员函数，它会带有一个 DW_AT_object_pointer 属性。
        // 这个属性指向 this 参数对应的 DIE（即 formal parameter DIE）。
        // 这个 DIE 描述了 this 参数，包括它的类型。
        std::vector<zdb::TypedData> args;
        auto& proc = target.get_process();
        if (object) {
            std::vector<std::byte> data;
            if (object->address()) { 
                data = zdb::to_byte_vec(*object->address());
            }
            else {
                auto& regs = proc.get_registers(tid);
                auto rsp = regs.read_by_id_as<std::uint64_t>(zdb::RegisterId::rsp);
                rsp -= object->value_type().byte_size();
                proc.write_memory(zdb::VirtualAddr{ rsp }, object->data());
                regs.write_by_id(zdb::RegisterId::rsp, rsp, true);
                data = zdb::to_byte_vec(rsp);
            }
            auto obj_ptr_die = funcs[0][DW_AT_object_pointer].as_reference();
            auto this_type = obj_ptr_die[DW_AT_type].as_type();
            args.push_back({ std::move(data), this_type });
        }
        
        auto args_start = 1;
        auto args_end = arg_string.find(')');
        while (args_start < args_end) {
            auto comma_pos = arg_string.find(',', args_start);
            if (comma_pos == std::string::npos) {
                comma_pos = args_end;
            }
        
            auto arg_expr = arg_string.substr(args_start, comma_pos - args_start);
            args.push_back(parse_single_augment(target, tid, arg_expr));
            args_start = comma_pos + 1;
        }
        return args;
    }

    zdb::DIE resolve_overload(
        const std::vector<zdb::DIE>& funcs,
        const std::vector<zdb::TypedData> args
    ) {
        std::optional<zdb::DIE> matched_func;
        for (auto& func : funcs) {
            bool is_matched_this_time = true;
            std::vector<zdb::Type> param_types = func.parameter_types();
            if (param_types.size() == args.size()) {
                auto param_it = param_types.begin();
                auto arg_it = args.begin();
                for (; arg_it != args.end(); ++param_it, ++arg_it) {
                    if (*param_it != arg_it->value_type()) {
                        is_matched_this_time = false;
                        break;
                    }
                }
            } else {
                is_matched_this_time = false;
            }

            if (is_matched_this_time) {
                if (matched_func) {
                    zdb::Error::send("Ambiguous function call");
                }
                matched_func = func;
            }
        }

        if (!matched_func) {
            zdb::Error::send("No matching function");
        }
        return *matched_func;
    }

    zdb::TypedData get_initial_variable_data(
        const zdb::Target& target, 
        std::string name, 
        zdb::FileAddr pc
    ) {
        if (name[0] == '$') {
            auto index = zdb::to_integral<std::size_t>(name.substr(1));
            if (!index) {
                zdb::Error::send("Invalid expression result index");
            }
            return target.get_expression_result(*index);
        }

        std::optional<zdb::DIE> var_die = target.find_variable(name, pc);
        if (!var_die) {
            zdb::Error::send("Variable not found");
        }

        zdb::Type var_type = var_die.value()[DW_AT_type].as_type();
        zdb::DwarfExpression::result loc = var_die
            .value()
            [DW_AT_location]
            .as_evaluated_location(
                target.get_process(),
                target.get_stack().current_frame().regs, 
                false);
        
        auto data_vec = target.read_location_data(
            loc, 
            var_type.byte_size()
        );

        std::optional<zdb::VirtualAddr> address;
        if (auto single_loc = 
            std::get_if<zdb::DwarfExpression::simple_location>(&loc)
        ) {
            if (auto addr_res =
                std::get_if<zdb::DwarfExpression::address_result>(single_loc)
            ) {
                address = addr_res->address;
            }
        }
        return { std::move(data_vec), var_type, address };
    }

    std::unique_ptr<zdb::ELF> create_loaded_elf(    
        const zdb::Process &process, 
        const std::filesystem::path &path
    ) {
        auto auxv = process.get_auxv();
        std::unique_ptr<zdb::ELF> elf = std::make_unique<zdb::ELF>(path);
        elf->notify_loaded(zdb::VirtualAddr(
            // load_bias_ = 
            //  actual memory address of the program entry point 
            //  - load address in elf phisical elf file
            auxv[AT_ENTRY] - elf->get_elf_header().e_entry
        ));

        return elf;
    }

    std::filesystem::path dump_vdso(const zdb::Process& proc, zdb::VirtualAddr address) {
        char tmp_dir[] = "/tmp/sdb-XXXXXX";
        mkdtemp(tmp_dir);
        std::filesystem::path vdso_dump_path = std::filesystem::path(tmp_dir) / "linux-vdso.so.1";
        std::ofstream vdso_dump(vdso_dump_path, std::ios::binary);
        Elf64_Ehdr vdso_header = proc.read_memory_as<Elf64_Ehdr>(address);
        auto vdso_size = 
            vdso_header.e_shoff + vdso_header.e_shentsize * vdso_header.e_shnum;
        std::vector<std::byte> vdso_bytes = proc.read_memory(address, vdso_size);
        vdso_dump.write(reinterpret_cast<const char*>(vdso_bytes.data()), vdso_bytes.size());
        return vdso_dump_path;
    }
}

std::unique_ptr<zdb::Target> zdb::Target::launch(
    std::filesystem::path path,
    std::optional<int> stdout_fd
) {
    auto process = Process::launch(path, true, stdout_fd);
    auto elf = create_loaded_elf(*process, path);
    auto target = std::unique_ptr<Target>(
        new Target(std::move(process), std::move(elf))
    );
    target->process_->set_target(target.get());
    auto entry_point = VirtualAddr{ target->get_process().get_auxv()[AT_ENTRY] };
    auto& entry_bp = target->create_address_breakpoint(entry_point, true, false);
    entry_bp.install_hit_handler([tgt = target.get()] {
        tgt->resolve_dynamic_linker_rendezvous();
        return true;
    });
    entry_bp.enable();
    return target;
}

std::unique_ptr<zdb::Target> zdb::Target::attach(pid_t pid) {
    // We need a way to find the ELF file associated with a given PID.
    // The /proc/<pid>/exe file is a symbolic link to the executable 
    // for the given process.
    auto elf_path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto proc = Process::attach(pid);
    auto obj = create_loaded_elf(*proc, elf_path);
    auto target = std::unique_ptr<Target>(
        new Target(std::move(proc), std::move(obj))
    );
    target->process_->set_target(target.get());
    target->resolve_dynamic_linker_rendezvous();
    return target;
}

zdb::FileAddr zdb::Target::get_pc_file_address(std::optional<pid_t> otid) const {
    return process_->get_pc(otid).to_file_addr(elves_);
}

zdb::LineTable::iterator zdb::Target::line_entry_at_pc(std::optional<pid_t> otid) const {
    FileAddr pc = get_pc_file_address(otid);
    if (!pc.elf()) return LineTable::iterator();
    const CompileUnit* cu = pc.elf()->get_dwarf().compile_unit_containing_address(pc);
    if (!cu) return LineTable::iterator();
    return cu->lines().get_entry_by_address(pc);
}

std::vector<zdb::LineTable::iterator> zdb::Target::get_line_entries_by_line(
    std::filesystem::path path, 
    std::size_t line
) const {
    std::vector<zdb::LineTable::iterator> entries;
    elves_.for_each([&](zdb::ELF& elf) {
        for (auto& cu : elf.get_dwarf().compile_units()) {
            auto new_entries = cu->lines().get_entries_by_line(path, line);
            entries.insert(entries.end(), new_entries.begin(), new_entries.end());
        }
    });
    return entries;
}

zdb::StopReason zdb::Target::run_until_address(VirtualAddr address, std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    BreakpointSite* breakpoint_to_remove = nullptr;
    if (!process_->breakpoint_sites().contains_address(address)) {
        breakpoint_to_remove = &process_->create_breakpoint_site(
            address, 
            true,
            false
        );
        breakpoint_to_remove->enable();
    }
    process_->resume(tid);
    auto reason = process_->wait_on_signal(tid);
    if (reason.is_breakpoint() && process_->get_pc(tid) == address) {
        reason.trap_type = TrapType::SignalStep;
    }
    if (breakpoint_to_remove) {
        process_->breakpoint_sites().remove_by_address(breakpoint_to_remove->address());
    }
    threads_.at(tid).state->reason = reason;
    return reason;
}

void zdb::Target::notify_stop(const StopReason& reason) {
    threads_.at(reason.tid).frames.unwind();
}

void zdb::Target::notify_thread_lifecycle_event(const zdb::StopReason& reason) {
    auto tid = reason.tid;
    if (reason.reason == ProcessState::Stopped) {
        auto& state = process_->thread_states()[tid];
        threads_.emplace(tid, Thread{ &state, Stack{this, tid} });
    }
    else {
        threads_.erase(tid);
    }
}

zdb::StopReason zdb::Target::step_in(std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);
    auto& thread = threads_.at(tid);

    if (stack.inline_height() > 0) {
        stack.simulate_inlined_step_in();
        StopReason reason(tid, ProcessState::Stopped, SIGTRAP, TrapType::SignalStep);
        thread.state->reason = reason;
        return reason;
    }

    auto orig_line = line_entry_at_pc(tid);
    do {
        auto reason = process_->step(tid);
        if (!reason.is_step()) {
            // Stopped at a breakpoint or terminated completely
            thread.state->reason = reason;
            return reason;
        }
    } while ((line_entry_at_pc(tid) == orig_line || line_entry_at_pc(tid)->end_sequence)
            && line_entry_at_pc(tid) != LineTable::iterator{});

    // we may still need to step over the function prologue
    // if we’ve entered a new function
    auto pc = get_pc_file_address(tid);
    if (pc.elf() != nullptr) {
        auto& dwarf = pc.elf()->get_dwarf();
        auto func = dwarf.function_containing_address(pc);
        if (func && func->low_pc() == pc) {
            auto line = line_entry_at_pc(tid);
            if (line != LineTable::iterator{}) {
                ++line;
                return run_until_address(line->address.to_virt_addr(), tid);
            }
        }
    }

    StopReason reason(tid, ProcessState::Stopped, SIGTRAP, TrapType::SignalStep, std::nullopt);
    thread.state->reason = reason;
    return reason;
}

zdb::StopReason zdb::Target::step_over(std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);
    auto& thread = threads_.at(tid);

    LineTable::iterator orig_line = line_entry_at_pc(tid);
    Disassembler disas(*process_);

    zdb::StopReason reason;
    do {
        auto inline_stack = stack.inline_stack_at_pc();
        auto at_start_of_inline_frame = stack.inline_height() > 0;
        if (at_start_of_inline_frame) {
            // This implementation of skipping inline frames will work in most cases
            // with unoptimized code, but it’s not necessarily the case that control flow
            // will hit the instruction directly after the inlined block after completing its
            // execution. Production debuggers will look for any branch instructions in
            // the inlined block, and if they find any, will step through the inlined block by
            // putting breakpoints at each branch instruction until the program makes it
            // out of the program counter ranges for the inlined function. This approach
            // is significantly more complex, so I’ve opted for the simpler solution here.
            DIE frame_to_skip = inline_stack[inline_stack.size() - stack.inline_height()];
            VirtualAddr return_address = frame_to_skip.high_pc().to_virt_addr();
            reason = run_until_address(return_address, tid);
            if (!reason.is_step() || process_->get_pc(tid) != return_address) {
                thread.state->reason = reason;
                return reason;
            }
        }
        else if (
            auto instructions = disas.disassemble(2, process_->get_pc(tid));
            instructions[0].text.rfind("call") == 0
        ) {
            reason = run_until_address(instructions[1].address, tid);
            if (!reason.is_step() || process_->get_pc(tid) != instructions[1].address) {
                thread.state->reason = reason;
                return reason;
            }
        }
        else {
            reason = process_->step(tid);
            if (!reason.is_step()) {
                thread.state->reason = reason;
                return reason;
            }
        }
    } while ((line_entry_at_pc(tid) == orig_line || line_entry_at_pc(tid)->end_sequence)
        && line_entry_at_pc(tid) != LineTable::iterator{});
    thread.state->reason = reason;
    return reason;
}

zdb::StopReason zdb::Target::step_out(std::optional<pid_t> otid) {
    // Recall the simplified x64 stack we discussed in Chapter 2, in which each
    // stack frame contains the return address of the current function. However,
    // while the program is running, it’s not clear how to locate exactly where on
    // the stack the return address is. We can figure this out in two main ways.
    // The more robust way of determining this location is to parse the DWARF
    // information for details about the call frame. While parsing the DWARF is
    // the robust way to solve this problem, it’s also quite complex. We’ll do this in
    // Chapter 16, when we implement full stack unwinding.
    // In this section, we rely on using specific compiler options when building 
    // the program to debug, which is `-fno-omit-frame-pointer`. the frame base of the 
    // currently executing function gets stored in the rbp register.
    // The rbp register points to the memory location directly following the return address 
    // for the currently executing function, so to figure out where to set a breakpoint 
    // to step out, we just need to read the memory 8 bytes above the current value of rbp. 
    // If we’re inside of an inlined function, we instead find the end address of the inlined 
    // block. With this knowledge, we can now implement step_out:
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);

    std::vector<DIE> inline_stack = stack.inline_stack_at_pc();
    bool has_inline_frames = inline_stack.size() > 1;
    bool at_inline_frame = stack.inline_height() < inline_stack.size() - 1;
    if (has_inline_frames && at_inline_frame) {
        DIE current_frame = inline_stack[inline_stack.size() - stack.inline_height() - 1];
        VirtualAddr return_address = current_frame.high_pc().to_virt_addr();
        return run_until_address(return_address, tid);
    }

    // // Before: 
    // // One place where this algorithm fails to work properly is if the program is halted inside 
    // // a recursive function at least one level deep. In that case, trying to step out may actually 
    // // step into another function call, because the return address can be hit by a recursive call. 
    // // We’ll address this case in Chapter 16, where we’ll implement stack unwinding.
    // auto frame_pointer = process_
    //     ->get_registers()
    //     .read_by_id_as<std::uint64_t>(RegisterId::rbp);

    // auto return_address = process_
    //     ->read_memory_as<std::uint64_t>(VirtualAddr{ frame_pointer + 8 });
    // return run_until_address(VirtualAddr{ return_address });

    // Now:
    // 最终的栈展开规则：
    // 假设 实际函数A中调用实际函数B，实际函数B调用内联C,内联C调用内联D,pc在内联D
    // Stack frames: [实际函数B, 内联C, 内联D, 实际函数A]
    const zdb::Registers& regs = stack.frames()[stack.current_frame_index() + 1].regs;
    VirtualAddr return_address{ regs.read_by_id_as<std::uint64_t>(RegisterId::rip) };
    zdb::StopReason reason;
    for (std::size_t frames = stack.frames().size(); stack.frames().size() >= frames;) {
        reason = run_until_address(return_address, tid);
        if (!reason.is_breakpoint() || process_->get_pc(tid) != return_address) {
            return reason;
        }
    }
    return reason;
}

zdb::Target::find_functions_result zdb::Target::find_functions(std::string name) const {
    find_functions_result result;
    elves_.for_each([&](zdb::ELF& elf) {
        std::vector<DIE> dwarf_found = elf.get_dwarf().find_functions(name);
        if (dwarf_found.empty()) {
            std::vector<const Elf64_Sym*> elf_found = elf.get_symbols_by_name(name);
            for (const Elf64_Sym* sym : elf_found) {
                result.elf_functions.push_back(std::pair{ &elf, sym });
            }
        }
        else {
            result.dwarf_functions.insert(
                result.dwarf_functions.end(),
                dwarf_found.begin(), 
                dwarf_found.end()
            );
        }
    });
    
    return result;
}

namespace zdb {
    Breakpoint& Target::create_address_breakpoint(
        VirtualAddr address,
        bool internal,
        bool hardware
    ) {
        return breakpoints_.push(
            std::unique_ptr<AddressBreakpoint>(
                new AddressBreakpoint(*this, address, internal, hardware)
            )
        );
    }

    Breakpoint& Target::create_function_breakpoint(
        std::string function_name,
        bool internal,
        bool hardware
    ) {
        return breakpoints_.push(
            std::unique_ptr<FunctionBreakpoint>(
                new FunctionBreakpoint(*this, function_name, internal, hardware)
            )
        );
    }

    Breakpoint& Target::create_line_breakpoint(
        std::filesystem::path file, 
        std::size_t line,
        bool internal,
        bool hardware
    ) {
        return breakpoints_.push(
            std::unique_ptr<LineBreakpoint>(
                new LineBreakpoint(*this, file, line, internal, hardware)
            )
        );
    }

    std::string Target::function_name_at_address(VirtualAddr address) const {
        FileAddr file_address = address.to_file_addr(elves_);
        const ELF* obj = file_address.elf();
        if (!obj) return "";

        std::optional<DIE> func = obj->get_dwarf().function_containing_address(file_address);
        std::string elf_filename = obj->path().filename().string();
        std::string func_name = "";

        if (func && func->name()) {
            // return std::string{func->name().value()};
            func_name = func->name().value();
        }
        else if (
            std::optional<const Elf64_Sym*> elf_func = obj->get_symbol_at_file_addr(file_address);
            elf_func && ELF64_ST_TYPE(elf_func.value()->st_info) == STT_FUNC
        ) {

            func_name = obj->get_general_str_from_strtab(elf_func.value()->st_name);
            // return abi::__cxa_demangle(
            //     elf_name.c_str(),
            //     nullptr,
            //     nullptr,
            //     nullptr
            // );
        }
        if (!func_name.empty()) 
            return elf_filename + "`" + func_name;

        return "";
    }

    void Target::resolve_dynamic_linker_rendezvous() {
        if (dynamic_linker_rendezvous_address_.addr()) return;

        std::optional<const Elf64_Shdr *>  dynamic_section = main_elf_->get_section_shdr_by_name(".dynamic");
        FileAddr dynamic_start = FileAddr{*main_elf_, dynamic_section.value()->sh_addr};
        std::size_t dynamic_size = dynamic_section.value()->sh_size;
        std::vector<std::byte> dynamic_bytes = 
            process_->read_memory(dynamic_start.to_virt_addr(), dynamic_size);
        
        std::vector<Elf64_Dyn> dynamic_entries(dynamic_size / sizeof(Elf64_Dyn));
        std::copy(
            dynamic_bytes.begin(), 
            dynamic_bytes.end(),
            reinterpret_cast<std::byte*>(dynamic_entries.data())
        );

        for (auto entry : dynamic_entries) {
            if (entry.d_tag == DT_DEBUG) {
                dynamic_linker_rendezvous_address_ = zdb::VirtualAddr{ entry.d_un.d_ptr };
                reload_dynamic_libraries();
                std::optional<r_debug> debug_info = read_dynamic_linker_rendezvous();
                VirtualAddr debug_state_addr = zdb::VirtualAddr{ debug_info->r_brk };
                Breakpoint& debug_state_bp = create_address_breakpoint(
                    debug_state_addr, 
                    true,
                    false
                );
                debug_state_bp.install_hit_handler(
                    [&] {
                        reload_dynamic_libraries();
                        return true;
                    }
                );
                debug_state_bp.enable();
            }
        }

    }

    std::optional<r_debug> Target::read_dynamic_linker_rendezvous() const {
        if (dynamic_linker_rendezvous_address_.addr()) {
            return process_->read_memory_as<r_debug>(dynamic_linker_rendezvous_address_);
        }
        return std::nullopt;
    }

    void Target::reload_dynamic_libraries() {
        std::optional<r_debug> debug = read_dynamic_linker_rendezvous();
        if (!debug) return;

        link_map* entry_ptr = debug->r_map;
        while (entry_ptr != nullptr) {
            VirtualAddr entry_addr = VirtualAddr(reinterpret_cast<std::uint64_t>(entry_ptr));
            link_map entry = process_->read_memory_as<link_map>(entry_addr);
            entry_ptr = entry.l_next;

            VirtualAddr name_addr = VirtualAddr(reinterpret_cast<std::uint64_t>(entry.l_name));
            std::vector<std::byte> name_bytes = process_->read_memory(name_addr, 4096);
            std::filesystem::path name = 
                std::filesystem::path{ reinterpret_cast<char*>(name_bytes.data()) };
            if (name.empty()) continue;

            const ELF* found = nullptr;
            const auto vdso_name = "linux-vdso.so.1";
            if (name == vdso_name) {
                found = elves_.get_elf_by_filename(name.c_str());
            }
            else {
                found = elves_.get_elf_by_path(name);
            }

            if (!found) {
                if (name == vdso_name) {
                    name = dump_vdso(*process_, VirtualAddr{ entry.l_addr });
                }
                auto new_elf = std::make_unique<ELF>(name);
                new_elf->notify_loaded(VirtualAddr{ entry.l_addr });
                elves_.push(std::move(new_elf));
            }
        }
        breakpoints_.for_each([&](auto& bp) {
            bp->resolve();
        });
    }

    std::vector<std::byte> Target::read_location_data(
        const DwarfExpression::result& loc, 
        std::size_t size,
        std::optional<pid_t> otid
    ) const {
        auto tid = otid.value_or(process_->current_thread());
        if (auto simple_loc = std::get_if<DwarfExpression::simple_location>(&loc)) {
            if (auto reg_loc = std::get_if<DwarfExpression::register_result>(simple_loc)) {
                const zdb::RegisterInfo& reg_info = find_register_info_by_dwarf_id(reg_loc->reg_num);
                Registers::Value reg_value = threads_.at(tid).frames.current_frame().regs.read(reg_info);
                auto get_bytes = [](auto value) {
                    std::vector<std::byte> bytes(sizeof(value));
                    auto begin = reinterpret_cast<const std::byte*>(&value);
                    std::copy(begin, begin + sizeof(value), bytes.data());
                    return bytes;
                };
                return std::visit(get_bytes, reg_value);
            }
            else if (auto addr_res = std::get_if<DwarfExpression::address_result>(simple_loc)) {
                return process_->read_memory(addr_res->address, size);
            }
            else if (auto data_res = std::get_if<DwarfExpression::data_result>(simple_loc)) {
                return { data_res->data.begin(), data_res->data.end() };
            }
            else if (auto literal_res = std::get_if<DwarfExpression::literal_result>(simple_loc)) {
                auto begin = reinterpret_cast<const std::byte*>(&literal_res->value);
                return { begin, begin + size };
            }
            else if (auto pieces_res = std::get_if<DwarfExpression::pieces_result>(&loc)) {
                std::vector<std::byte> data(size);
                std::size_t offset = 0; // 返回值data的当前位偏移
                for (auto& piece : pieces_res->pieces) {
                    auto byte_size = (piece.bit_size + 7) / 8;
                    auto piece_data = read_location_data(piece.location, byte_size, otid);
                    if (offset % 8 == 0 && piece.offset == 0 && piece.bit_size % 8 == 0) {
                        std::copy(piece_data.begin(), piece_data.end(), data.begin() + offset / 8);
                        offset += piece.bit_size;
                    } 
                    else {
                        auto dest = reinterpret_cast<std::uint8_t*>(data.data());
                        auto src = reinterpret_cast<const std::uint8_t*>(piece_data.data());
                        // 从src的piece.offset开始, 读取piece.bit_size位的数据,复制到dest里
                        memcpy_bits(dest, 0, src, piece.offset, piece.bit_size);
                    }
                }
                return data;
            }

            Error::send("Invalid simple location type");
        }
    }

    // like: a.b | a->b | a[1] 
    // 我们不支持 * 或&操作符来解引用和获取地址，因为只使用后缀操作符会大大简化解析;
    // 可以使用[0]来代替 * 操作符。我们将添加一个变量位置命令，他们可以使用它来代替&操作符
    Target::resolve_indirect_name_result 
    Target::resolve_indirect_name(std::string name, FileAddr pc) const {
        std::size_t op_pos = name.find_first_of(".-[(");
        if (name[op_pos] == '(') {
            auto func_name = name.substr(0, op_pos);
            auto funcs = find_functions(func_name);
            return { std::nullopt, std::move(funcs.dwarf_functions) };
        }

        std::string var_name = name.substr(0, op_pos);
        const zdb::Dwarf& dwarf = pc.elf()->get_dwarf();
        TypedData data = get_initial_variable_data(*this, var_name, pc);

        while (op_pos != std::string::npos) {
            if (name[op_pos] == '-') {
                if (name[op_pos + 1] != '>') {
                    zdb::Error::send("Invalid operator");
                }
                data = data.deref_pointer(get_process());
                op_pos++;
            }

            if (name[op_pos] == '.' || name[op_pos] == '>') {
                std::size_t member_name_start = op_pos + 1;
                op_pos = name.find_first_of(".-[(", member_name_start);
                std::string member_name = name.substr(
                    member_name_start, 
                    op_pos - member_name_start
                );

                if (name[op_pos] == '(') {
                    std::vector<DIE> funcs;
                    zdb::Type striped_data = data.value_type().strip_cvref_typedef();
                    for (auto& child : data.value_type().get_die().children()) {
                        if (child.abbrev_entry()->tag == DW_TAG_subprogram
                            && child.name() == member_name
                            && child.contains(DW_AT_object_pointer)
                        ) {
                            funcs.push_back(child);
                        }
                    }

                    if (funcs.empty()) {
                        Error::send("No such member function");
                    }
                    return { std::move(data), std::move(funcs) };
                }

                data = data.read_member(get_process(), member_name);
                name = name.substr(member_name_start);
            }
            else if (name[op_pos] == '[') {
                std::size_t int_end = name.find(']', op_pos);
                std::string index_str = name.substr(op_pos + 1, int_end - op_pos - 1);
                std::optional<std::size_t> index = to_integral<std::size_t>(index_str);
                if (!index) {
                    zdb::Error::send("Invalid index");
                }
                data = data.index(get_process(), *index);
                name = name.substr(int_end + 1);
            }
            op_pos = name.find_first_of(".-[(,");
        }
        return { std::move(data), {} };
    }

    std::optional<DIE> Target::find_variable(std::string name, FileAddr pc) const {
        const zdb::Dwarf &dwarf = pc.elf()->get_dwarf();
        std::optional<zdb::DIE> local_die = dwarf.find_local_variable(name, pc);
        if (local_die) {
            return local_die;
        }
        
        std::optional<DIE> global = std::nullopt;
        elves_.for_each([&](zdb::ELF& elf) {
            auto& dwarf = elf.get_dwarf();
            auto found = dwarf.find_global_variable(name);
            if (found) {
                global = *found;
            }
        });
        return global;
    }

    VirtualAddr Target::inferior_malloc(std::size_t size) {
        auto saved_regs = process_->get_registers();

        // 我们找到malloc的定义，它位于libc实现中。假设用户没有使用libc的调试版本，
        // 所以Target::find_functions将在ELF符号表中找到它，而不是在DWARF信息中。
        // 如果希望支持libc的调试版本，可以同时检查这两个选项。
        auto candidate_malloc_funcs = find_functions("malloc").elf_functions;
        auto malloc_func = std::find_if(
            candidate_malloc_funcs.begin(), 
            candidate_malloc_funcs.end(), 
            [](std::pair<const ELF*, const Elf64_Sym*>& sym) {
                return sym.second->st_value != 0;
            }
        );

        if (malloc_func == candidate_malloc_funcs.end()) {
            zdb::Error::send("malloc not found");
        }

        FileAddr malloc_func_addr{*malloc_func->first, malloc_func->second->st_value};
        VirtualAddr malloc_call_addr = malloc_func_addr.to_virt_addr();
        VirtualAddr entry_addr{process_->get_auxv()[AT_ENTRY]};
        breakpoints_.get_by_address(entry_addr).install_hit_handler([&] {
            return false;
        });

        // malloc(size),将第一个参数size 写入rdi寄存器
        process_->get_registers().write_by_id(RegisterId::rdi, size, true);
        auto new_regs = process_->inferior_call(
            malloc_call_addr, 
            entry_addr, 
            saved_regs
        );

        auto result = new_regs.read_by_id_as<std::uint64_t>(RegisterId::rax);
        return VirtualAddr{ result };
    }


    std::optional<Target::evaluate_expression_result> Target::evaluate_expression(
        std::string_view expr,
        std::optional<pid_t> otid
    ) {
        auto tid = otid.value_or(process_->current_thread());
        auto pc = get_pc_file_address(tid);
        auto paren_pos = expr.find('(');
        if (paren_pos == std::string::npos) {
            zdb::Error::send("Invalid expression");
        }
        std::string name{ expr.substr(0, paren_pos + 1) };
        auto [variable, funcs] = resolve_indirect_name(name, pc);
        if (funcs.empty()) {
            zdb::Error::send("Invalid expression");
        }

        auto entry_point = VirtualAddr{ process_->get_auxv()[AT_ENTRY] };
        breakpoints_.get_by_address(entry_point).install_hit_handler([&] {
            return false;
        });

        auto arg_string = expr.substr(paren_pos);
        auto args = collect_arguments(
            *this, 
            tid, 
            arg_string, 
            funcs, 
            variable
        );
        auto func = resolve_overload(funcs, args);
        auto ret = inferior_call_from_dwarf(
            *this, 
            func, 
            args, 
            entry_point, 
            tid
        );

        if (ret) {
            expression_results_.push_back(*ret);
            return evaluate_expression_result{
                expression_results_.size() - 1,
                std::move(*ret)
            };
        }
        return std::nullopt;
    }

    const TypedData& Target::get_expression_result(std::size_t i) const {
        auto& res = expression_results_[i];
        auto new_data = process_->read_memory(
            *res.address(), 
            res.value_type().byte_size()
        );

        res = TypedData {
            std::move(new_data), 
            res.value_type(), 
            res.address() 
        };
        return res;
        
    }
}; // namespace zdb;

        
